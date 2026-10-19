
const encoder = new TextEncoder();

const cors = {
  "Content-Type": "application/json; charset=utf-8",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

function reply(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: cors });
}

function b64(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: 210000,
    hash: "SHA-256"
  }, key, 256);
  return b64(bits);
}

async function makePassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { salt: b64(salt), hash: await hashPassword(password, salt) };
}

async function verifyPassword(password, saltText, expected) {
  const salt = Uint8Array.from(
    atob(saltText.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - saltText.length % 4) % 4)),
    c => c.charCodeAt(0)
  );
  const actual = await hashPassword(password, salt);
  return actual === expected;
}

async function tokenFor(user, secret) {
  const header = b64(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64(encoder.encode(JSON.stringify({
    sub: String(user.id),
    companyId: String(user.company_id),
    role: user.role,
    iat: now,
    exp: now + 7200
  })));
  const data = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  return data + "." + b64(await crypto.subtle.sign("HMAC", key, encoder.encode(data)));
}

async function authenticate(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return null;

  const parts = header.slice(7).split(".");
  if (parts.length !== 3) return null;

  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(env.JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "HMAC", key,
    Uint8Array.from(atob(parts[2].replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - parts[2].length % 4) % 4)), c => c.charCodeAt(0)),
    encoder.encode(parts[0] + "." + parts[1])
  );
  if (!valid) return null;

  const payload = JSON.parse(atob(
    parts[1].replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - parts[1].length % 4) % 4)
  ));
  if (!payload.sub || !payload.companyId || payload.exp <= Date.now() / 1000)
    return null;
  return payload;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    if (!env.DB) return reply({ error: "D1 binding DB is not configured" }, 503);
    if (!env.JWT_SECRET) return reply({ error: "JWT_SECRET is not configured" }, 503);

    try {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS arx_companies (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
      `).run();

      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS arx_users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          company_id INTEGER NOT NULL,
          email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          password_salt TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'owner',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
      `).run();

      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS arx_customers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          company_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          phone TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
      `).run();

      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS arx_products (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          company_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          quantity REAL NOT NULL DEFAULT 0,
          price REAL NOT NULL DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
      `).run();

      if (url.pathname === "/" || url.pathname === "/health") {
        return reply({
          app: "ARx Business Plus",
          server: "ok",
          database: "connected"
        });
      }

      if (request.method === "POST" && url.pathname === "/register") {
        const body = await request.json();
        const companyName = String(body.companyName || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = body.password;

        if (!companyName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            typeof password !== "string" || password.length < 12) {
          return reply({ error: "اسم الشركة وبريد صحيح وكلمة مرور 12 حرفًا على الأقل مطلوبة" }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM arx_users WHERE email = ?"
        ).bind(email).first();
        if (existing) return reply({ error: "البريد مسجل بالفعل" }, 409);

        const pw = await makePassword(password);
        const company = await env.DB.prepare(
          "INSERT INTO arx_companies(name) VALUES (?)"
        ).bind(companyName).run();

        const user = await env.DB.prepare(
          "INSERT INTO arx_users(company_id,email,password_hash,password_salt,role) VALUES (?,?,?,?,?)"
        ).bind(company.meta.last_row_id, email, pw.hash, pw.salt, "owner").run();

        const record = {
          id: user.meta.last_row_id,
          company_id: company.meta.last_row_id,
          email,
          role: "owner"
        };
        return reply({
          token: await tokenFor(record, env.JWT_SECRET),
          user: { id: record.id, email, role: record.role },
          company: { id: record.company_id, name: companyName }
        }, 201);
      }

      if (request.method === "POST" && url.pathname === "/login") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        if (typeof body.password !== "string" || !email)
          return reply({ error: "البريد وكلمة المرور مطلوبان" }, 400);

        const user = await env.DB.prepare(
          "SELECT * FROM arx_users WHERE email = ?"
        ).bind(email).first();

        if (!user || !(await verifyPassword(
          body.password, user.password_salt, user.password_hash
        ))) return reply({ error: "بيانات الدخول غير صحيحة" }, 401);

        return reply({
          token: await tokenFor(user, env.JWT_SECRET),
          user: { id: user.id, email: user.email, role: user.role, companyId: user.company_id }
        });
      }

      const protectedRoutes = ["/api/customers", "/api/products"];
      if (protectedRoutes.includes(url.pathname)) {
        const user = await authenticate(request, env);
        if (!user) return reply({ error: "تسجيل الدخول مطلوب أو انتهت الجلسة" }, 401);

        const table = url.pathname.endsWith("customers") ? "arx_customers" : "arx_products";

        if (request.method === "GET") {
          const result = await env.DB.prepare(
            `SELECT * FROM ${table} WHERE company_id = ? ORDER BY id DESC`
          ).bind(Number(user.companyId)).all();
          return reply(result.results);
        }

        if (request.method === "POST") {
          const body = await request.json();
          const name = String(body.name || "").trim();
          if (!name) return reply({ error: "الاسم مطلوب" }, 400);

          if (table === "arx_customers") {
            const result = await env.DB.prepare(
              "INSERT INTO arx_customers(company_id,name,phone) VALUES (?,?,?)"
            ).bind(Number(user.companyId), name, String(body.phone || "").trim() || null).run();
            return reply({ id: result.meta.last_row_id, name, phone: body.phone || null }, 201);
          }

          const quantity = Number(body.quantity ?? 0);
          const price = Number(body.price ?? 0);
          if (!Number.isFinite(quantity) || !Number.isFinite(price) ||
              quantity < 0 || price < 0)
            return reply({ error: "الكمية والسعر يجب أن يكونا أرقامًا غير سالبة" }, 400);

          const result = await env.DB.prepare(
            "INSERT INTO arx_products(company_id,name,quantity,price) VALUES (?,?,?,?)"
          ).bind(Number(user.companyId), name, quantity, price).run();
          return reply({ id: result.meta.last_row_id, name, quantity, price }, 201);
        }
      }

      return reply({ error: "المسار غير موجود" }, 404);
    } catch (error) {
      console.error("ARx API error:", error);
      return reply({ error: "حدث خطأ داخلي؛ راجع سجلات Worker" }, 500);
    }
  }
};
