// Supabase Edge Function «love» — кнопка «Я тебя люблю ❤️» в обе стороны.
// Один файл, без зависимостей: Web Push (VAPID + шифрование aes128gcm) сделан на WebCrypto,
// база — через REST API Supabase (PostgREST) с сервисным ключом.
//
// Секреты функции (Edge Functions → Secrets):
//   VAPID_PUBLIC_KEY   — из keygen.html
//   VAPID_PRIVATE_KEY  — из keygen.html
//   VAPID_SUBJECT      — mailto:ваш@email
//   FAMILY_KEY         — из keygen.html (общий ключ семьи, вводится на каждом телефоне)
//   ALLOWED_ORIGIN     — https://ВАШ_ЛОГИН.github.io  (можно несколько через запятую)
// SUPABASE_URL и SUPABASE_SERVICE_ROLE_KEY Supabase подставляет сам.

const enc = new TextEncoder();
const PUSH_HOSTS = [
  /(^|\.)push\.apple\.com$/,
  /(^|\.)fcm\.googleapis\.com$/,
  /(^|\.)android\.googleapis\.com$/,
  /(^|\.)push\.services\.mozilla\.com$/,
  /(^|\.)notify\.windows\.com$/,
];

// ───────────── base64url ─────────────
function b64uToBytes(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64u(bytes) {
  let bin = "";
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function concat(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// ───────────── Web Push ─────────────
async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

let vapidKeyCache = null;
async function vapidPrivateKey(pubB64u, privB64u) {
  if (vapidKeyCache) return vapidKeyCache;
  const pub = b64uToBytes(pubB64u);
  if (pub.length !== 65 || pub[0] !== 4) throw new Error("bad VAPID_PUBLIC_KEY");
  const jwk = {
    kty: "EC", crv: "P-256", ext: true,
    x: bytesToB64u(pub.slice(1, 33)),
    y: bytesToB64u(pub.slice(33, 65)),
    d: privB64u,
  };
  vapidKeyCache = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return vapidKeyCache;
}

async function vapidAuth(endpoint, env) {
  const aud = new URL(endpoint).origin;
  const header = bytesToB64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = bytesToB64u(enc.encode(JSON.stringify({
    aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT,
  })));
  const unsigned = `${header}.${claims}`;
  const key = await vapidPrivateKey(env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(unsigned));
  return `vapid t=${unsigned}.${bytesToB64u(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

// RFC 8291 (Message Encryption for Web Push) + RFC 8188 (aes128gcm)
export async function encryptPayload(payload, p256dhB64u, authB64u) {
  const uaPublic = b64uToBytes(p256dhB64u);
  const authSecret = b64uToBytes(authB64u);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));

  const prkKey = await hmac(authSecret, ecdhSecret);
  const keyInfo = concat(enc.encode("WebPush: info\0"), uaPublic, asPublic, new Uint8Array([1]));
  const ikm = await hmac(prkKey, keyInfo);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, concat(enc.encode("Content-Encoding: aes128gcm\0"), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc.encode("Content-Encoding: nonce\0"), new Uint8Array([1])))).slice(0, 12);

  const plain = concat(enc.encode(payload), new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, plain));

  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

export async function sendPush(sub, payloadObj, env, ttl = 43200) {
  const body = await encryptPayload(JSON.stringify(payloadObj), sub.keys.p256dh, sub.keys.auth);
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      Authorization: await vapidAuth(sub.endpoint, env),
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: String(ttl),
      Urgency: "high",
    },
    body,
  });
  let text = "";
  try { text = (await res.text()).slice(0, 200); } catch { /* ignore */ }
  return { status: res.status, text };
}

// ───────────── база (PostgREST) ─────────────
function db(env) {
  const base = `${env.SUPABASE_URL}/rest/v1`;
  const key = env.SERVICE_KEY;
  const headers = { apikey: key, "Content-Type": "application/json" };
  if (key.startsWith("eyJ")) headers.Authorization = `Bearer ${key}`; // старые JWT-ключи
  async function q(path, opts = {}) {
    const res = await fetch(`${base}/${path}`, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`db ${res.status}: ${t.slice(0, 300)}`);
    }
    const t = await res.text();
    return t ? JSON.parse(t) : null;
  }
  return {
    devices: () => q("devices?select=id,sub&order=updated_at.asc"),
    device: async (id) => (await q(`devices?select=id,sub&id=eq.${encodeURIComponent(id)}`))[0] || null,
    upsertDevice: (row) => q("devices?on_conflict=id", {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify({ ...row, updated_at: new Date().toISOString() }),
    }),
    deleteDevice: (id) => q(`devices?id=eq.${encodeURIComponent(id)}`, { method: "DELETE" }),
  };
}

// ───────────── проверки ─────────────
function safeEqual(a, b) {
  a = enc.encode(String(a || ""));
  b = enc.encode(String(b || ""));
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a[i] || 0) ^ (b[i] || 0);
  return diff === 0 && a.length > 0;
}

function validSub(s) {
  if (!s || typeof s !== "object" || typeof s.endpoint !== "string" || !s.keys) return false;
  if (s.endpoint.length > 1000) return false;
  let u;
  try { u = new URL(s.endpoint); } catch { return false; }
  if (u.protocol !== "https:" || !PUSH_HOSTS.some((r) => r.test(u.hostname))) return false;
  const { p256dh, auth } = s.keys;
  if (typeof p256dh !== "string" || typeof auth !== "string") return false;
  if (!/^[A-Za-z0-9_-]{80,100}$/.test(p256dh) || !/^[A-Za-z0-9_-]{16,32}$/.test(auth)) return false;
  return b64uToBytes(p256dh).length === 65 && b64uToBytes(auth).length === 16;
}

const validId = (s) => typeof s === "string" && /^[A-Za-z0-9-]{8,64}$/.test(s);

// ───────────── обработчик ─────────────
export async function handle(req, env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = String(env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim().replace(/\/$/, "")).filter(Boolean);
  const okOrigin = allowed.includes(origin);
  const cors = {
    "Access-Control-Allow-Origin": okOrigin ? origin : (allowed[0] || "null"),
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, authorization, apikey, x-client-info",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
  const json = (status, obj) => new Response(JSON.stringify(obj), {
    status, headers: { ...cors, "Content-Type": "application/json; charset=utf-8" },
  });

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") return json(405, { ok: false, error: "method" });

  let body;
  try {
    const t = await req.text();
    if (t.length > 8000) return json(413, { ok: false, error: "too_large" });
    body = JSON.parse(t || "{}");
  } catch { return json(400, { ok: false, error: "bad_json" }); }

  const action = body.action;

  // Пинг без ключа: держит бесплатный проект «живым» (Supabase усыпляет проекты без активности)
  if (action === "ping") {
    try { await db(env).devices(); return json(200, { ok: true }); }
    catch (e) { console.error("ping", e); return json(503, { ok: false, error: "storage" }); }
  }

  if (origin && !okOrigin) return json(403, { ok: false, error: "origin" });

  const missing = ["VAPID_PUBLIC_KEY", "VAPID_PRIVATE_KEY", "VAPID_SUBJECT", "FAMILY_KEY", "SUPABASE_URL", "SERVICE_KEY"]
    .filter((k) => !env[k]);
  if (missing.length) {
    console.error("missing env:", missing.join(", "));
    return json(500, { ok: false, error: "server_config" });
  }

  // Публичный ключ VAPID — без авторизации (он и так публичный)
  if (action === "config") return json(200, { ok: true, vapidPublicKey: env.VAPID_PUBLIC_KEY });

  if (!safeEqual(body.key, env.FAMILY_KEY)) return json(401, { ok: false, error: "unauthorized" });

  const store = db(env);
  try {
    if (action === "register") {
      if (!validId(body.deviceId)) return json(400, { ok: false, error: "bad_device" });
      if (!validSub(body.subscription)) return json(400, { ok: false, error: "bad_subscription" });
      const sub = { endpoint: body.subscription.endpoint, keys: { p256dh: body.subscription.keys.p256dh, auth: body.subscription.keys.auth } };
      const cur = await store.device(body.deviceId);
      if (!cur || JSON.stringify(cur.sub) !== JSON.stringify(sub)) {
        await store.upsertDevice({ id: body.deviceId, sub });
      }
      const all = await store.devices();
      return json(200, { ok: true, others: all.filter((d) => d.id !== body.deviceId).length });
    }

    if (action === "unregister") {
      if (!validId(body.deviceId)) return json(400, { ok: false, error: "bad_device" });
      await store.deleteDevice(body.deviceId);
      return json(200, { ok: true });
    }

    if (action === "status") {
      const all = await store.devices();
      const me = validId(body.deviceId) ? all.find((d) => d.id === body.deviceId) : null;
      return json(200, {
        ok: true, registered: !!me,
        others: all.filter((d) => d.id !== body.deviceId).length,
      });
    }

    if (action === "send") {
      if (!validId(body.deviceId)) return json(400, { ok: false, error: "bad_device" });
      const me = await store.device(body.deviceId);
      if (!me) return json(409, { ok: false, error: "not_registered" });
      const targets = (await store.devices()).filter((d) => d.id !== me.id);
      if (!targets.length) return json(409, { ok: false, error: "no_recipients" });

      const payload = { title: "❤️", body: "Я тебя люблю ❤️", ts: Date.now() };
      const results = await Promise.all(targets.map(async (d) => {
        try {
          const r = await sendPush(d.sub, payload, env);
          if (r.status === 404 || r.status === 410) {
            await store.deleteDevice(d.id);
            return { ok: false, gone: true };
          }
          if (r.status < 200 || r.status >= 300) console.error("push", r.status, r.text);
          return { ok: r.status >= 200 && r.status < 300, status: r.status };
        } catch (e) {
          console.error("push error", e);
          return { ok: false };
        }
      }));
      const delivered = results.filter((r) => r.ok).length;
      const gone = results.filter((r) => r.gone).length;
      if (!delivered) return json(502, { ok: false, error: gone ? "recipients_gone" : "push_failed" });
      return json(200, { ok: true, delivered });
    }

    return json(400, { ok: false, error: "bad_action" });
  } catch (e) {
    console.error(action, e);
    return json(503, { ok: false, error: "storage" });
  }
}

function envFromDeno() {
  const g = (k) => Deno.env.get(k) || "";
  return {
    VAPID_PUBLIC_KEY: g("VAPID_PUBLIC_KEY").trim(),
    VAPID_PRIVATE_KEY: g("VAPID_PRIVATE_KEY").trim(),
    VAPID_SUBJECT: g("VAPID_SUBJECT").trim(),
    FAMILY_KEY: g("FAMILY_KEY").trim(),
    ALLOWED_ORIGIN: g("ALLOWED_ORIGIN"),
    SUPABASE_URL: g("SUPABASE_URL"),
    SERVICE_KEY: g("SUPABASE_SERVICE_ROLE_KEY") || g("SERVICE_KEY"),
  };
}

if (typeof Deno !== "undefined" && Deno.serve) {
  Deno.serve((req) => handle(req, envFromDeno()));
}
