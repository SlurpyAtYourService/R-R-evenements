import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import helmet from "helmet";
import session from "express-session";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import crypto from "crypto";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const ORDERS_FILE = path.join(DATA_DIR, "orders.json");
const TOTP_FILE = path.join(DATA_DIR, "totp.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, "[]", "utf-8");

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });
const ordersLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });

app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "dev_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", maxAge: 1000 * 60 * 60 * 8 },
  })
);

app.use(express.static(path.join(__dirname, "public")));

const readOrders = () => JSON.parse(fs.readFileSync(ORDERS_FILE, "utf-8"));
const writeOrders = (orders) =>
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2));

const getTotpSecret = () => {
  if (!fs.existsSync(TOTP_FILE)) return null;
  return JSON.parse(fs.readFileSync(TOTP_FILE, "utf-8"))?.base32 || null;
};

const setTotpSecret = (base32) => {
  fs.writeFileSync(TOTP_FILE, JSON.stringify({ base32 }, null, 2));
};

// ==========================
// One-time setup for TOTP
// ==========================
app.get("/admin/setup", async (req, res) => {
  const { token } = req.query;
  if (token !== process.env.SETUP_TOKEN)
    return res.status(403).send("Invalid setup token");

  let base32 = getTotpSecret();
  if (!base32) {
    const secret = speakeasy.generateSecret({
      name: `${process.env.TOTP_ISSUER}:${process.env.TOTP_LABEL}`,
      issuer: process.env.TOTP_ISSUER,
      length: 20,
    });
    base32 = secret.base32;
    setTotpSecret(base32);
  }

  const otpauth = `otpauth://totp/${process.env.TOTP_ISSUER}:${process.env.TOTP_LABEL}?secret=${base32}&issuer=${process.env.TOTP_ISSUER}&period=30&digits=6`;
  const qr = await QRCode.toDataURL(otpauth);

  res.send(`
    <h1>TOTP Setup</h1>
    <p>Scan this QR in Google Authenticator:</p>
    <img src="${qr}" />
    <p>Secret: ${base32}</p>
  `);
});

// ==========================
// Verify TOTP
// ==========================
app.post("/api/auth/totp", authLimiter, (req, res) => {
  const { code } = req.body;
  const secretBase32 = getTotpSecret();
  if (!secretBase32) return res.status(500).json({ ok: false });

  const verified = speakeasy.totp.verify({
    secret: secretBase32,
    encoding: "base32",
    token: code,
    window: 1,
  });

  if (!verified) return res.status(401).json({ ok: false, error: "Invalid" });

  req.session.authenticated = true;
  res.json({ ok: true });
});

const requireAuth = (req, res, next) => {
  if (req.session?.authenticated) return next();
  return res.status(401).json({ ok: false });
};

// ==========================
// Orders
// ==========================
app.post("/api/orders", ordersLimiter, (req, res) => {
  const { name, address, items } = req.body;
  if (!name || !address || !Array.isArray(items))
    return res.status(400).json({ ok: false });

  const orders = readOrders();
  const order = {
    id: crypto.randomUUID(),
    name,
    address,
    items,
    status: "pending",
    createdAt: new Date().toISOString(),
  };
  orders.push(order);
  writeOrders(orders);
  res.json({ ok: true, order });
});

app.get("/api/orders", requireAuth, (req, res) => {
  res.json({ ok: true, orders: readOrders() });
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
