
import express from "express";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(cookieParser());

app.use(express.static(__dirname));

const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  message: { error: "Too many attempts. Try again later." }
});

function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;

  if (!token) {
    return res.status(401).json({ error: "Login required" });
  }

  try {
    req.admin = jwt.verify(token, process.env.aniga_waaye);
    next();
  } catch {
    res.clearCookie("admin_token");
    return res.status(401).json({ error: "Session expired" });
  }
}

app.post("/api/admin/login", loginLimit, (req, res) => {
  const { password } = req.body;

  if (!process.env.sirta_waaye || !process.env.aniga_waaye) {
    return res.status(503).json({
      error: "Admin security is not configured"
    });
  }

  if (password !== process.env.sirta_waaye) {
    return res.status(401).json({
      error: "Incorrect password"
    });
  }

  const token = jwt.sign(
    { role: "admin" },
    process.env.aniga_waaye,
    { expiresIn: "8h" }
  );

  res.cookie("admin_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000
  });

  res.json({ success: true });
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({ authenticated: true, role: "admin" });
});

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie("admin_token");
  res.json({ success: true });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "CodeShow Studio backend is running" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`CodeShow Studio running on port ${PORT}`);
});
