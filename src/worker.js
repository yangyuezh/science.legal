const SESSION_COOKIE = "orcid_session";
const STATE_COOKIE = "orcid_state";
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
      return redirect("https://www.webofscience.com");
    }

    if (url.pathname === "/auth/altmetric/login") {
      return redirect("https://www.altmetric.com/explorer/login");
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

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}
