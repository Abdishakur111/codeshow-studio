
import express from "express";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import { createClient } from "@supabase/supabase-js";

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

const supabaseReady =
  process.env.SUPABASE_URL &&
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = supabaseReady
  ? createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY,
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      }
    )
  : null;

const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  message: { error: "Too many attempts. Try again later." }
});

function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;

  if (!token) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  try {
    req.admin = jwt.verify(
      token,
      process.env.sirta_waaye
    );

    next();
  } catch {
    res.clearCookie("admin_token");
    return res.status(401).json({
      error: "Session expired"
    });
  }
}

function requireDatabase(req, res, next) {
  if (!supabase) {
    return res.status(503).json({
      error: "Database is not configured"
    });
  }

  next();
}

// ADMIN LOGIN
app.post("/api/admin/login", loginLimit, (req, res) => {
  const { password } = req.body;

  if (
    !process.env.aniga_waaye ||
    !process.env.sirta_waaye
  ) {
    return res.status(503).json({
      error: "Admin security is not configured"
    });
  }

  if (password !== process.env.aniga_waaye) {
    return res.status(401).json({
      error: "Incorrect password"
    });
  }

  const token = jwt.sign(
    { role: "admin" },
    process.env.sirta_waaye,
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

// CHECK ADMIN SESSION
app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    authenticated: true,
    role: "admin"
  });
});

// ADMIN DASHBOARD STATISTICS
app.get(
  "/api/admin/stats",
  requireAdmin,
  requireDatabase,
  async (req, res) => {
    try {
      const [
        usersResult,
        subscriptionsResult,
        activeSubscriptionsResult,
        adsResult,
        activeAdsResult,
        revenueResult
      ] = await Promise.all([
        supabase.auth.admin.listUsers({
          page: 1,
          perPage: 1000
        }),

        supabase
          .from("subscriptions")
          .select("id", { count: "exact", head: true }),

        supabase
          .from("subscriptions")
          .select("id", { count: "exact", head: true })
          .eq("status", "active"),

        supabase
          .from("advertisements")
          .select("id", { count: "exact", head: true }),

        supabase
          .from("advertisements")
          .select("id", { count: "exact", head: true })
          .eq("status", "active"),

        supabase
          .from("revenue_events")
          .select("amount")
      ]);

      const results = [
        usersResult,
        subscriptionsResult,
        activeSubscriptionsResult,
        adsResult,
        activeAdsResult,
        revenueResult
      ];

      for (const result of results) {
        if (result.error) throw result.error;
      }

      const revenuePence = revenueResult.data.reduce(
        (total, item) => total + Number(item.amount || 0),
        0
      );

      res.json({
        totalUsers: usersResult.data.users.length,
        premiumMembers: activeSubscriptionsResult.count || 0,
        totalSubscriptions: subscriptionsResult.count || 0,
        advertisements: adsResult.count || 0,
        activeAdvertisements: activeAdsResult.count || 0,
        revenueGBP: revenuePence / 100
      });

    } catch (error) {
      console.error("Admin stats error:", error);

      res.status(500).json({
        error: "Could not load dashboard statistics"
      });
    }
  }
);

// ADMIN USERS
app.get(
  "/api/admin/users",
  requireAdmin,
  requireDatabase,
  async (req, res) => {
    try {
      const { data, error } =
        await supabase.auth.admin.listUsers({
          page: 1,
          perPage: 100
        });

      if (error) throw error;

      res.json({
        users: data.users.map(user => ({
          id: user.id,
          email: user.email,
          created_at: user.created_at,
          last_sign_in_at: user.last_sign_in_at
        }))
      });

    } catch (error) {
      console.error("Users error:", error);
      res.status(500).json({
        error: "Could not load users"
      });
    }
  }
);

// ADMIN SUBSCRIPTIONS
app.get(
  "/api/admin/subscriptions",
  requireAdmin,
  requireDatabase,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("subscriptions")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) throw error;

      res.json({ subscriptions: data });

    } catch (error) {
      console.error("Subscriptions error:", error);
      res.status(500).json({
        error: "Could not load subscriptions"
      });
    }
  }
);

// ADMIN ADVERTISEMENTS
app.get(
  "/api/admin/advertisements",
  requireAdmin,
  requireDatabase,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("advertisements")
        .select("*")
        .order("created_at", { ascending: false });

      if (error) throw error;

      res.json({ advertisements: data });

    } catch (error) {
      console.error("Advertisements error:", error);
      res.status(500).json({
        error: "Could not load advertisements"
      });
    }
  }
);

// ADMIN REVENUE
app.get(
  "/api/admin/revenue",
  requireAdmin,
  requireDatabase,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("revenue_events")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) throw error;

      res.json({
        revenue: data,
        currency: "GBP"
      });

    } catch (error) {
      console.error("Revenue error:", error);
      res.status(500).json({
        error: "Could not load revenue"
      });
    }
  }
);

// ADMIN LOGOUT
app.post("/api/admin/logout", (req, res) => {
  res.clearCookie("admin_token");
  res.json({ success: true });
});

// HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({
    status: "CodeShow Studio backend is running",
    databaseConfigured: Boolean(supabase)
  });
});

// HOME PAGE
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`CodeShow Studio running on port ${PORT}`);
});
