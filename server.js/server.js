const express = require("express");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

dotenv.config();

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.get("/", (req, res) => {
  res.json({
    app: "ARx Business Plus",
    status: "server_running",
    message: "API is online"
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ server: "ok", database: "connected" });
  } catch (error) {
    res.status(503).json({
      server: "ok",
      database: "not_configured"
    });
  }
});

app.post("/setup", async (req, res) => {
  if (!process.env.SETUP_KEY ||
      req.get("x-setup-key") !== process.env.SETUP_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS companies (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        company_id BIGINT NOT NULL REFERENCES companies(id),
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'owner',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS customers (
        id BIGSERIAL PRIMARY KEY,
        company_id BIGINT NOT NULL REFERENCES companies(id),
        name TEXT NOT NULL,
        phone TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS products (
        id BIGSERIAL PRIMARY KEY,
        company_id BIGINT NOT NULL REFERENCES companies(id),
        name TEXT NOT NULL,
        quantity NUMERIC NOT NULL DEFAULT 0,
        price NUMERIC NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS employees (
        id BIGSERIAL PRIMARY KEY,
        company_id BIGINT NOT NULL REFERENCES companies(id),
        name TEXT NOT NULL,
        job_title TEXT
      );
    `);

    res.json({ success: true, message: "Tables created" });
  } catch (error) {
    console.error("Setup failed:", error.message);
    res.status(500).json({ error: "Database setup failed" });
  }
});

app.post("/register", async (req, res) => {
  const { companyName, email, password } = req.body || {};

  if (!companyName || !email ||
      typeof password !== "string" || password.length < 12) {
    return res.status(400).json({
      error: "Company, email and password (12+ characters) required"
    });
  }

  if (!JWT_SECRET) {
    return res.status(503).json({ error: "Server configuration incomplete" });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const company = await client.query(
      "INSERT INTO companies(name) VALUES($1) RETURNING id, name",
      [companyName]
    );

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await client.query(
      `INSERT INTO users(company_id, email, password_hash, role)
       VALUES($1, $2, $3, 'owner')
       RETURNING id, company_id, email, role`,
      [company.rows[0].id, email.toLowerCase(), passwordHash]
    );

    await client.query("COMMIT");

    const token = jwt.sign({
      sub: String(user.rows[0].id),
      companyId: String(user.rows[0].company_id),
      role: user.rows[0].role
    }, JWT_SECRET, { expiresIn: "2h" });

    res.status(201).json({
      user: user.rows[0],
      company: company.rows[0],
      token
    });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: "Registration failed; check email and database" });
  } finally {
    client.release();
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password || !JWT_SECRET) {
    return res.status(400).json({ error: "Email and password required" });
  }

  try {
    const result = await pool.query(
      `SELECT id, company_id, email, password_hash, role
       FROM users WHERE email = $1`,
      [email.toLowerCase()]
    );

    if (!result.rows.length ||
        !(await bcrypt.compare(password, result.rows[0].password_hash))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const token = jwt.sign({
      sub: String(user.id),
      companyId: String(user.company_id),
      role: user.role
    }, JWT_SECRET, { expiresIn: "2h" });

    res.json({
      token,
      user: {
        id: user.id,
        companyId: user.company_id,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Login unavailable" });
  }
});

function authenticate(req, res, next) {
  const header = req.get("authorization") || "";

  if (!JWT_SECRET || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

app.get("/api/customers", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, phone, created_at FROM customers
       WHERE company_id = $1 ORDER BY id DESC`,
      [req.user.companyId]
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: "Could not load customers" });
  }
});

app.post("/api/customers", authenticate, async (req, res) => {
  const { name, phone } = req.body || {};

  if (!name || typeof name !== "string") {
    return res.status(400).json({ error: "Customer name required" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO customers(company_id, name, phone)
       VALUES($1, $2, $3) RETURNING id, name, phone`,
      [req.user.companyId, name, phone || null]
    );
    res.status(201).json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Could not save customer" });
  }
});

app.get("/api/products", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, quantity, price FROM products
       WHERE company_id = $1 ORDER BY id DESC`,
      [req.user.companyId]
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: "Could not load products" });
  }
});

app.post("/api/products", authenticate, async (req, res) => {
  const { name, quantity = 0, price = 0 } = req.body || {};

  if (!name || !Number.isFinite(Number(quantity)) ||
      !Number.isFinite(Number(price)) ||
      Number(quantity) < 0 || Number(price) < 0) {
    return res.status(400).json({ error: "Invalid product data" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO products(company_id, name, quantity, price)
       VALUES($1, $2, $3, $4)
       RETURNING id, name, quantity, price`,
      [req.user.companyId, name, quantity, price]
    );
    res.status(201).json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Could not save product" });
  }
});

app.listen(PORT, () => {
  console.log(`ARx Business Plus API listening on ${PORT}`);
});
      
