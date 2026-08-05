import crypto from "node:crypto";
import { Readable } from "node:stream";
import express from "express";
import { SignJWT, jwtVerify } from "jose";

const baseUrl = (process.env.PUBLIC_BASE_URL || process.env.RENDER_EXTERNAL_URL || "").replace(/\/$/, "");
const required = {
  baseUrl,
  apiKey: process.env.APPARELMAGIC_API_KEY,
  adminPassword: process.env.OAUTH_ADMIN_PASSWORD,
  jwtSecret: process.env.JWT_SECRET,
};

for (const [name, value] of Object.entries(required)) {
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
}

const config = {
  port: Number(process.env.PORT || 3000),
  baseUrl,
  issuer: baseUrl,
  upstreamUrl: process.env.UPSTREAM_MCP_URL || "https://api.apparelmagic.com/mcp",
  apiKey: process.env.APPARELMAGIC_API_KEY,
  adminPassword: process.env.OAUTH_ADMIN_PASSWORD,
  jwtSecret: new TextEncoder().encode(process.env.JWT_SECRET),
  scope: process.env.OAUTH_SCOPE || "mcp:tools:read",
};

const app = express();
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "20mb", type: ["application/json", "application/*+json"] }));

const usedAuthorizationCodes = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [jti, expiresAt] of usedAuthorizationCodes.entries()) {
    if (expiresAt <= now) usedAuthorizationCodes.delete(jti);
  }
}, 60_000).unref();

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function sha256Base64Url(value) {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  })[char]);
}

async function sign(payload, expiresIn, audience) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(config.issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .setJti(crypto.randomUUID())
    .sign(config.jwtSecret);
}

async function verify(token, audience) {
  return jwtVerify(token, config.jwtSecret, {
    issuer: config.issuer,
    audience,
    algorithms: ["HS256"],
  });
}

function oauthError(res, status, error, description) {
  res.status(status).json({ error, error_description: description });
}

const oauthMetadata = {
  issuer: config.issuer,
  authorization_endpoint: `${config.baseUrl}/authorize`,
  token_endpoint: `${config.baseUrl}/token`,
  registration_endpoint: `${config.baseUrl}/register`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none"],
  scopes_supported: [config.scope, "offline_access"],
};

const resourceMetadata = {
  resource: `${config.baseUrl}/mcp`,
  authorization_servers: [config.issuer],
  scopes_supported: [config.scope],
  bearer_methods_supported: ["header"],
};

app.get("/.well-known/oauth-authorization-server", (_req, res) => res.json(oauthMetadata));
app.get("/.well-known/openid-configuration", (_req, res) => res.json(oauthMetadata));
app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json(resourceMetadata));
app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => res.json(resourceMetadata));

app.post("/register", async (req, res) => {
  const redirectUris = req.body?.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every((uri) => typeof uri === "string")) {
    return oauthError(res, 400, "invalid_client_metadata", "redirect_uris is required");
  }

  for (const uri of redirectUris) {
    try {
      const parsed = new URL(uri);
      const local = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
      if (parsed.protocol !== "https:" && !local) {
        return oauthError(res, 400, "invalid_redirect_uri", "Redirect URIs must use HTTPS or localhost");
      }
    } catch {
      return oauthError(res, 400, "invalid_redirect_uri", "Invalid redirect URI");
    }
  }

  const clientId = await sign({
    type: "oauth_client",
    redirect_uris: redirectUris,
    client_name: String(req.body?.client_name || "ChatGPT MCP Client"),
  }, "365d", "oauth-client");

  res.status(201).json({
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_name: String(req.body?.client_name || "ChatGPT MCP Client"),
    redirect_uris: redirectUris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  });
});

async function validateAuthParams(input) {
  const params = {
    response_type: String(input.response_type || ""),
    client_id: String(input.client_id || ""),
    redirect_uri: String(input.redirect_uri || ""),
    code_challenge: String(input.code_challenge || ""),
    code_challenge_method: String(input.code_challenge_method || ""),
    state: input.state ? String(input.state) : undefined,
    scope: input.scope ? String(input.scope) : config.scope,
    resource: input.resource ? String(input.resource) : `${config.baseUrl}/mcp`,
  };

  if (params.response_type !== "code") throw new Error("Only response_type=code is supported");
  if (!params.client_id || !params.redirect_uri) throw new Error("Missing client_id or redirect_uri");
  if (!params.code_challenge || params.code_challenge_method !== "S256") throw new Error("PKCE S256 is required");
  if (params.resource !== `${config.baseUrl}/mcp`) throw new Error("Invalid resource");

  const { payload } = await verify(params.client_id, "oauth-client");
  if (!Array.isArray(payload.redirect_uris) || !payload.redirect_uris.includes(params.redirect_uri)) {
    throw new Error("redirect_uri is not registered");
  }
  return params;
}

function loginPage(params, error = "") {
  const hidden = Object.entries(params)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
    .join("\n");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NOWADAYS ApparelMagic</title>
<style>body{font-family:system-ui;max-width:480px;margin:60px auto;padding:24px;background:#f3f4f6}.card{background:#fff;padding:28px;border-radius:16px;box-shadow:0 8px 30px #0001}input,button{box-sizing:border-box;width:100%;padding:13px;margin-top:12px;border-radius:9px;border:1px solid #bbb}button{background:#111;color:#fff;border:0;font-weight:700}.error{color:#b00020}</style>
</head><body><div class="card"><h2>NOWADAYS × ApparelMagic</h2><p>Authorize ChatGPT to access ApparelMagic with the configured read permissions.</p>${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}<form method="post" action="/authorize">${hidden}<label>Password<input type="password" name="password" autocomplete="current-password" required autofocus></label><button type="submit">Authorize</button></form></div></body></html>`;
}

app.get("/authorize", async (req, res) => {
  try {
    const params = await validateAuthParams(req.query);
    res.type("html").send(loginPage(params));
  } catch (error) {
    oauthError(res, 400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
});

app.post("/authorize", async (req, res) => {
  try {
    const params = await validateAuthParams(req.body);
    if (!safeEqual(req.body.password || "", config.adminPassword)) {
      return res.status(401).type("html").send(loginPage(params, "Incorrect password"));
    }

    const code = await sign({
      type: "authorization_code",
      client_id: params.client_id,
      redirect_uri: params.redirect_uri,
      code_challenge: params.code_challenge,
      scope: params.scope,
      resource: params.resource,
    }, "5m", "oauth-code");

    const redirect = new URL(params.redirect_uri);
    redirect.searchParams.set("code", code);
    if (params.state) redirect.searchParams.set("state", params.state);
    res.redirect(302, redirect.toString());
  } catch (error) {
    oauthError(res, 400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
});

app.post("/token", async (req, res) => {
  try {
    const grantType = String(req.body.grant_type || "");
    const clientId = String(req.body.client_id || "");
    await verify(clientId, "oauth-client");

    if (grantType === "authorization_code") {
      const code = String(req.body.code || "");
      const verifier = String(req.body.code_verifier || "");
      const redirectUri = String(req.body.redirect_uri || "");
      const { payload, protectedHeader } = await verify(code, "oauth-code");
      void protectedHeader;

      if (payload.type !== "authorization_code" || payload.client_id !== clientId || payload.redirect_uri !== redirectUri) {
        return oauthError(res, 400, "invalid_grant", "Authorization code is invalid");
      }
      if (!verifier || sha256Base64Url(verifier) !== payload.code_challenge) {
        return oauthError(res, 400, "invalid_grant", "PKCE verification failed");
      }
      if (!payload.jti || usedAuthorizationCodes.has(payload.jti)) {
        return oauthError(res, 400, "invalid_grant", "Authorization code was already used");
      }
      usedAuthorizationCodes.set(payload.jti, Date.now() + 10 * 60_000);

      const accessToken = await sign({ type: "access_token", scope: payload.scope, resource: payload.resource }, "1h", `${config.baseUrl}/mcp`);
      const refreshToken = await sign({ type: "refresh_token", scope: payload.scope, resource: payload.resource, client_id: clientId }, "30d", "oauth-refresh");
      return res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, refresh_token: refreshToken, scope: payload.scope });
    }

    if (grantType === "refresh_token") {
      const refreshToken = String(req.body.refresh_token || "");
      const { payload } = await verify(refreshToken, "oauth-refresh");
      if (payload.type !== "refresh_token" || payload.client_id !== clientId) {
        return oauthError(res, 400, "invalid_grant", "Refresh token is invalid");
      }
      const accessToken = await sign({ type: "access_token", scope: payload.scope, resource: payload.resource }, "1h", `${config.baseUrl}/mcp`);
      const rotatedRefreshToken = await sign({ type: "refresh_token", scope: payload.scope, resource: payload.resource, client_id: clientId }, "30d", "oauth-refresh");
      return res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, refresh_token: rotatedRefreshToken, scope: payload.scope });
    }

    return oauthError(res, 400, "unsupported_grant_type", "Supported grants: authorization_code, refresh_token");
  } catch (error) {
    return oauthError(res, 400, "invalid_grant", error instanceof Error ? error.message : "Token request failed");
  }
});

async function requireAccessToken(req, res) {
  const auth = req.get("authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    res.set("WWW-Authenticate", `Bearer resource_metadata="${config.baseUrl}/.well-known/oauth-protected-resource/mcp"`);
    res.status(401).json({ error: "unauthorized" });
    return false;
  }

  try {
    const { payload } = await verify(auth.slice(7), `${config.baseUrl}/mcp`);
    if (payload.type !== "access_token") throw new Error("Wrong token type");
    return true;
  } catch {
    res.set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="${config.baseUrl}/.well-known/oauth-protected-resource/mcp"`);
    res.status(401).json({ error: "invalid_token" });
    return false;
  }
}

app.all("/mcp", async (req, res) => {
  if (!(await requireAccessToken(req, res))) return;

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (!value || ["host", "authorization", "content-length", "connection"].includes(key.toLowerCase())) continue;
    headers.set(key, Array.isArray(value) ? value.join(", ") : String(value));
  }
  headers.set("X-API-Key", config.apiKey);

  const hasBody = !["GET", "HEAD"].includes(req.method);
  const body = hasBody ? JSON.stringify(req.body ?? {}) : undefined;
  if (hasBody && !headers.has("content-type")) headers.set("content-type", "application/json");

  try {
    const upstream = await fetch(config.upstreamUrl, {
      method: req.method,
      headers,
      body,
      redirect: "manual",
    });

    res.status(upstream.status);
    upstream.headers.forEach((value, key) => {
      if (!["content-encoding", "content-length", "transfer-encoding", "connection"].includes(key.toLowerCase())) {
        res.set(key, value);
      }
    });

    if (!upstream.body) return res.end();
    Readable.fromWeb(upstream.body).pipe(res);
  } catch (error) {
    res.status(502).json({
      error: "upstream_error",
      message: error instanceof Error ? error.message : "Upstream request failed",
    });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true, service: "nowadays-apparelmagic-mcp" }));
app.get("/", (_req, res) => res.type("text").send("NOWADAYS ApparelMagic MCP OAuth proxy is running."));

app.listen(config.port, () => {
  console.log(`Listening on port ${config.port}`);
  console.log(`MCP endpoint: ${config.baseUrl}/mcp`);
});
