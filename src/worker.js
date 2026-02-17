const SESSION_COOKIE = "orcid_session";
const STATE_COOKIE = "orcid_state";
const WOS_SESSION_COOKIE = "wos_session";
const WOS_STATE_COOKIE = "wos_state";
const WOS_PORTAL_COOKIE = "wos_portal";
const ALTMETRIC_PORTAL_COOKIE = "altmetric_portal";
const SESSION_MAX_AGE = 60 * 60 * 24 * 30;
const STATE_MAX_AGE = 60 * 10;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Keep auth flow on one canonical origin to avoid state/cookie mismatches.
    if (url.protocol !== "https:" || url.hostname === "www.science.legal") {
      const redirect = new URL(url.toString());
      redirect.protocol = "https:";
      if (redirect.hostname === "www.science.legal") redirect.hostname = "science.legal";
      return new Response(null, {
        status: 301,
        headers: { Location: redirect.toString() }
      });
    }

    if (url.pathname === "/auth/orcid/login") {
      try {
        return await handleLogin(request, env, url);
      } catch (err) {
        return redirectWithError("/orcid.html?error=orcid_not_configured");
      }
    }

    if (url.pathname === "/auth/orcid/callback") {
      try {
        return await handleCallback(request, env, url);
      } catch (err) {
        return redirectWithError("/orcid.html?error=orcid_callback_failed");
      }
    }

    if (url.pathname === "/auth/orcid/logout") {
      return handleLogout(url);
    }

    if (url.pathname === "/auth/wos/login") {
      try {
        return await handleWosLogin(request, env, url);
      } catch (err) {
        return redirectWithError("/wos.html?error=wos_login_failed");
      }
    }

    if (url.pathname === "/auth/wos/callback") {
      try {
        return await handleWosCallback(request, env, url);
      } catch (err) {
        return redirectWithError("/wos.html?error=wos_callback_failed");
      }
    }

    if (url.pathname === "/auth/wos/logout") {
      return handleWosLogout(url);
    }

    if (url.pathname === "/api/wos/me") {
      try {
        return await handleWosMe(request, env);
      } catch (err) {
        return json({ authenticated: false, error: "wos_not_configured" }, 200);
      }
    }

    if (url.pathname === "/auth/altmetric/login") {
      return handleAltmetricLogin(env);
    }

    if (url.pathname === "/auth/altmetric/logout") {
      return handleAltmetricLogout(url);
    }

    if (url.pathname === "/api/altmetric/me") {
      return handleAltmetricMe(request, env);
    }

    if (url.pathname === "/api/me") {
      try {
        return await handleMe(request, env);
      } catch (err) {
        return json({ authenticated: false, error: "orcid_not_configured" }, 200);
      }
    }

    return env.ASSETS.fetch(request);
  }
};

async function handleLogin(request, env, url) {
  const cfg = getConfig(env, url);
  const state = randomToken(24);
  const signedState = await signValue(state, cfg.sessionSecret);

  const auth = new URL(`${cfg.orcidBase}/oauth/authorize`);
  auth.searchParams.set("client_id", cfg.clientId);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", "/authenticate");
  auth.searchParams.set("redirect_uri", cfg.redirectUri);
  auth.searchParams.set("state", state);

  const headers = new Headers();
  headers.set("Location", auth.toString());
  headers.append("Set-Cookie", cookieHeader(STATE_COOKIE, signedState, STATE_MAX_AGE));

  return new Response(null, { status: 302, headers });
}

async function handleCallback(request, env, url) {
  const cfg = getConfig(env, url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookies = parseCookies(request.headers.get("Cookie"));
  const signedState = cookies[STATE_COOKIE];

  if (!code || !state || !signedState) {
    return redirectWithError("/orcid.html?error=missing_oauth_params");
  }

  const storedState = await verifySignedValue(signedState, cfg.sessionSecret);
  if (!storedState || storedState !== state) {
    return redirectWithError("/orcid.html?error=invalid_state");
  }

  const tokenRes = await fetch(`${cfg.orcidBase}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json"
    },
    body: new URLSearchParams({
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: cfg.redirectUri
    })
  });

  if (!tokenRes.ok) {
    return redirectWithError("/orcid.html?error=token_exchange_failed");
  }

  const token = await tokenRes.json();
  const orcid = token.orcid;
  const name = token.name || "";

  if (!orcid) {
    return redirectWithError("/orcid.html?error=missing_orcid");
  }

  const sessionPayload = {
    orcid,
    name,
    issued_at: new Date().toISOString()
  };
  const signedSession = await signValue(JSON.stringify(sessionPayload), cfg.sessionSecret);

  const headers = new Headers();
  headers.set("Location", "/orcid.html");
  headers.append("Set-Cookie", cookieHeader(SESSION_COOKIE, signedSession, SESSION_MAX_AGE));
  headers.append("Set-Cookie", clearCookieHeader(STATE_COOKIE));

  return new Response(null, { status: 302, headers });
}

function handleLogout(url) {
  const next = url.searchParams.get("next") || "/";
  const headers = new Headers();
  headers.set("Location", next);
  headers.append("Set-Cookie", clearCookieHeader(SESSION_COOKIE));
  headers.append("Set-Cookie", clearCookieHeader(STATE_COOKIE));
  return new Response(null, { status: 302, headers });
}

async function handleMe(request, env) {
  const cfg = getConfig(env, new URL(request.url));
  const cookies = parseCookies(request.headers.get("Cookie"));
  const signedSession = cookies[SESSION_COOKIE];

  if (!signedSession) {
    return json({ authenticated: false }, 200);
  }

  const raw = await verifySignedValue(signedSession, cfg.sessionSecret);
  if (!raw) {
    return json({ authenticated: false }, 200);
  }

  let session;
  try {
    session = JSON.parse(raw);
  } catch {
    return json({ authenticated: false }, 200);
  }

  return json({ authenticated: true, profile: session }, 200);
}

async function handleWosLogin(request, env, url) {
  const cfg = getWosConfig(env, url);
  const headers = new Headers();

  if (!cfg.oauthConfigured) {
    headers.set("Location", cfg.portalUrl);
    headers.append("Set-Cookie", cookieHeader(WOS_PORTAL_COOKIE, randomToken(12), STATE_MAX_AGE));
    return new Response(null, { status: 302, headers });
  }

  const state = randomToken(24);
  const signedState = await signValue(state, cfg.sessionSecret);
  const auth = new URL(cfg.authorizeUrl);
  auth.searchParams.set("client_id", cfg.clientId);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("redirect_uri", cfg.redirectUri);
  auth.searchParams.set("state", state);
  if (cfg.scope) auth.searchParams.set("scope", cfg.scope);

  headers.set("Location", auth.toString());
  headers.append("Set-Cookie", cookieHeader(WOS_STATE_COOKIE, signedState, STATE_MAX_AGE));
  return new Response(null, { status: 302, headers });
}

async function handleWosCallback(request, env, url) {
  const cfg = getWosConfig(env, url);
  if (!cfg.oauthConfigured) {
    return redirectWithError("/wos.html?error=wos_not_configured");
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookies = parseCookies(request.headers.get("Cookie"));
  const signedState = cookies[WOS_STATE_COOKIE];

  if (!code || !state || !signedState) {
    return redirectWithError("/wos.html?error=missing_oauth_params");
  }

  const storedState = await verifySignedValue(signedState, cfg.sessionSecret);
  if (!storedState || storedState !== state) {
    return redirectWithError("/wos.html?error=invalid_state");
  }

  let tokenRes = await fetch(cfg.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json"
    },
    body: new URLSearchParams({
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: cfg.redirectUri
    })
  });

  if (!tokenRes.ok) {
    // Some OAuth providers require Basic auth for token exchange.
    tokenRes = await fetch(cfg.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Authorization": `Basic ${btoa(`${cfg.clientId}:${cfg.clientSecret}`)}`
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: cfg.redirectUri
      })
    });
  }

  if (!tokenRes.ok) {
    return redirectWithError("/wos.html?error=token_exchange_failed");
  }

  const token = await tokenRes.json();
  const jwtPayload = token.id_token ? parseJwtPayload(token.id_token) : null;
  const profile = {
    provider: "webofscience",
    subject: token.sub || jwtPayload?.sub || "",
    name: token.name || jwtPayload?.name || "",
    email: token.email || jwtPayload?.email || "",
    scope: token.scope || "",
    issued_at: new Date().toISOString()
  };

  const signedSession = await signValue(JSON.stringify(profile), cfg.sessionSecret);
  const headers = new Headers();
  headers.set("Location", "/wos.html");
  headers.append("Set-Cookie", cookieHeader(WOS_SESSION_COOKIE, signedSession, SESSION_MAX_AGE));
  headers.append("Set-Cookie", clearCookieHeader(WOS_STATE_COOKIE));
  headers.append("Set-Cookie", clearCookieHeader(WOS_PORTAL_COOKIE));
  return new Response(null, { status: 302, headers });
}

function handleWosLogout(url) {
  const next = url.searchParams.get("next") || "/wos.html";
  const headers = new Headers();
  headers.set("Location", next);
  headers.append("Set-Cookie", clearCookieHeader(WOS_SESSION_COOKIE));
  headers.append("Set-Cookie", clearCookieHeader(WOS_STATE_COOKIE));
  headers.append("Set-Cookie", clearCookieHeader(WOS_PORTAL_COOKIE));
  return new Response(null, { status: 302, headers });
}

async function handleWosMe(request, env) {
  const cfg = getWosConfig(env, new URL(request.url));
  const cookies = parseCookies(request.headers.get("Cookie"));
  const signed = cookies[WOS_SESSION_COOKIE];
  const portalOpened = Boolean(cookies[WOS_PORTAL_COOKIE]);

  if (!signed) {
    return json(
      {
        authenticated: false,
        oauth_configured: cfg.oauthConfigured,
        portal_opened: portalOpened
      },
      200
    );
  }

  const raw = await verifySignedValue(signed, cfg.sessionSecret);
  if (!raw) {
    return json({ authenticated: false, oauth_configured: cfg.oauthConfigured }, 200);
  }

  let profile;
  try {
    profile = JSON.parse(raw);
  } catch {
    return json({ authenticated: false, oauth_configured: cfg.oauthConfigured }, 200);
  }

  return json({ authenticated: true, oauth_configured: cfg.oauthConfigured, profile }, 200);
}

function handleAltmetricLogin(env) {
  const portalUrl = env.ALTMETRIC_PORTAL_URL || "https://www.altmetric.com/explorer/login";
  const headers = new Headers();
  headers.set("Location", portalUrl);
  headers.append(
    "Set-Cookie",
    cookieHeader(ALTMETRIC_PORTAL_COOKIE, randomToken(12), STATE_MAX_AGE)
  );
  return new Response(null, { status: 302, headers });
}

function handleAltmetricLogout(url) {
  const next = url.searchParams.get("next") || "/altmetric.html";
  const headers = new Headers();
  headers.set("Location", next);
  headers.append("Set-Cookie", clearCookieHeader(ALTMETRIC_PORTAL_COOKIE));
  return new Response(null, { status: 302, headers });
}

function handleAltmetricMe(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const portalOpened = Boolean(cookies[ALTMETRIC_PORTAL_COOKIE]);
  const apiConfigured = Boolean(env.ALTMETRIC_API_KEY || env.ALTMETRIC_EXPLORER_API_KEY);

  return json(
    {
      authenticated: false,
      mode: "portal",
      portal_opened: portalOpened,
      api_configured: apiConfigured
    },
    200
  );
}

function getConfig(env, url) {
  const clientId = env.ORCID_CLIENT_ID;
  const clientSecret = env.ORCID_CLIENT_SECRET;
  const sessionSecret = env.SESSION_SECRET;

  if (!clientId || !clientSecret || !sessionSecret) {
    throw new Error("Missing ORCID_CLIENT_ID, ORCID_CLIENT_SECRET, or SESSION_SECRET");
  }

  const orcidBase = env.ORCID_BASE_URL || "https://orcid.org";
  const redirectUri = env.ORCID_REDIRECT_URI || `${url.origin}/auth/orcid/callback`;

  return {
    clientId,
    clientSecret,
    sessionSecret,
    orcidBase,
    redirectUri
  };
}

function getWosConfig(env, url) {
  const sessionSecret = env.SESSION_SECRET;
  if (!sessionSecret) throw new Error("Missing SESSION_SECRET");

  const clientId = env.WOS_CLIENT_ID || "";
  const clientSecret = env.WOS_CLIENT_SECRET || "";
  const authorizeUrl = env.WOS_AUTHORIZE_URL || "";
  const tokenUrl = env.WOS_TOKEN_URL || "";
  const redirectUri = env.WOS_REDIRECT_URI || `${url.origin}/auth/wos/callback`;
  const scope = env.WOS_SCOPE || "openid profile email";
  const portalUrl = env.WOS_PORTAL_URL || "https://www.webofscience.com";

  return {
    sessionSecret,
    clientId,
    clientSecret,
    authorizeUrl,
    tokenUrl,
    redirectUri,
    scope,
    portalUrl,
    oauthConfigured: Boolean(clientId && clientSecret && authorizeUrl && tokenUrl)
  };
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function redirectWithError(location) {
  return redirect(location);
}

function redirect(location) {
  return new Response(null, {
    status: 302,
    headers: { Location: location }
  });
}

function parseCookies(raw) {
  const out = {};
  if (!raw) return out;

  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (!k) continue;
    out[k] = decodeURIComponent(rest.join("="));
  }

  return out;
}

function cookieHeader(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearCookieHeader(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function randomToken(bytes) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return toBase64Url(data);
}

async function signValue(value, secret) {
  const sig = await hmac(value, secret);
  const payload = textToBase64Url(value);
  return `${payload}.${sig}`;
}

async function verifySignedValue(signed, secret) {
  const idx = signed.lastIndexOf(".");
  if (idx <= 0) return null;
  const payload = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);

  let value;
  try {
    value = base64UrlToText(payload);
  } catch {
    return null;
  }

  const expected = await hmac(value, secret);
  if (!constantTimeEqual(sig, expected)) return null;
  return value;
}

async function hmac(value, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(value));
  return toBase64Url(new Uint8Array(mac));
}

function toBase64Url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function textToBase64Url(text) {
  const bytes = new TextEncoder().encode(text);
  return toBase64Url(bytes);
}

function base64UrlToText(payload) {
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function parseJwtPayload(jwt) {
  const parts = String(jwt || "").split(".");
  if (parts.length < 2) return null;
  try {
    return JSON.parse(base64UrlToText(parts[1]));
  } catch {
    return null;
  }
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}
