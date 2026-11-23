
"use strict";

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const db = require("./database/db");

const app = express();
const PORT = process.env.PORT || 4000;

if (process.env.NODE_ENV === "production") {
  throw new Error("Production session configuration must be set before deployment.");
}

app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));

// Session: ana amfani da shi ne a gwajin localhost.
app.use(
  session({
    name: "wallet.sid",
    secret: process.env.SESSION_SECRET || "LOCAL-DEV-ONLY-CHANGE-THIS-SECRET-123456",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      secure: false,
      maxAge: 30 * 60 * 1000
    }
  })
);

// Health checks
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Digital Agent Wallet API yana aiki.",
    version: "1.0.0"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    application: "Digital Agent Wallet",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/health/database", (req, res) => {
  try {
    const result = db.prepare("SELECT 1 AS connected").get();

    res.json({
      success: true,
      database: "connected",
      message: "Wallet database yana aiki.",
      check: result.connected
    });
  } catch (error) {
    console.error("Database error:", error.message);
    res.status(500).json({
      success: false,
      database: "disconnected",
      message: "An kasa haɗawa da database."
    });
  }
});

// Login
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== "string" ||
    typeof password !== "string" ||
    !username.trim() ||
    !password ||
    username.length > 100 ||
    password.length > 200
  ) {
    return res.status(400).json({
      success: false,
      message: "Shigar da username da password masu inganci."
    });
  }

  try {
    const user = db.prepare(`
      SELECT id, username, password_hash, full_name, role, agent_id, is_active
      FROM users
      WHERE username = ?
    `).get(username.trim());

    // Saƙo ɗaya ne ko username bai wanzu ko password bai dace ba.
    if (!user || !user.is_active || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({
        success: false,
        message: "Username ko password ba daidai ba ne."
      });
    }

    req.session.regenerate((error) => {
      if (error) {
        console.error("Session error:", error.message);
        return res.status(500).json({
          success: false,
          message: "An kasa fara zaman login."
        });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        fullName: user.full_name,
        role: user.role,
        agentId: user.agent_id
      };

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save error:", saveError.message);
          return res.status(500).json({
            success: false,
            message: "An kasa adana zaman login."
          });
        }

        return res.json({
          success: true,
          message: "An shiga cikin nasara.",
          user: req.session.user
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({
      success: false,
      message: "An samu kuskure yayin login."
    });
  }
});

// Duba wanda ya shiga
app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      message: "Da fatan za ka fara login."
    });
  }

  res.json({
    success: true,
    user: req.session.user
  });
});

// Logout
app.post("/api/auth/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie("wallet.sid", {
      httpOnly: true,
      sameSite: "strict",
      secure: false
    });

    res.json({
      success: true,
      message: "An fita daga tsarin."
    });
  });
});

// Tabbatar da login
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      message: "Sai ka yi login kafin amfani da wannan hanya."
    });
  }

  next();
}

// Tabbatar da izinin role
function allowRoles(...roles) {
  return (req, res, next) => {
    if (!req.session.user || !roles.includes(req.session.user.role)) {
      return res.status(403).json({
        success: false,
        message: "Ba ka da izinin wannan aiki."
      });
    }

    next();
  };
}

// Gwajin role: Super Admin kaɗai
app.get(
  "/api/admin/overview",
  requireLogin,
  allowRoles("Super Admin"),
  (req, res) => {
    const counts = {
      users: db.prepare("SELECT COUNT(*) AS total FROM users").get().total,
      agents: db.prepare("SELECT COUNT(*) AS total FROM agents").get().total,
      transactions: db.prepare("SELECT COUNT(*) AS total FROM transactions").get().total
    };

    res.json({
      success: true,
      message: "Barka da zuwa Super Admin.",
      counts
    });
  }
);

// Route da babu shi
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Ba a sami wannan API endpoint ba."
  });
});

// Kuskuren server
app.use((err, req, res, next) => {
  console.error("Server error:", err.message);

  if (res.headersSent) return next(err);

  res.status(err.status || 500).json({
    success: false,
    message: err.status === 400
      ? "An aika da bayanan JSON marasa inganci."
      : "An samu kuskuren server."
  });
});

const server = app.listen(PORT, "127.0.0.1", () => {
  console.log("----------------------------------------");
  console.log(" DIGITAL AGENT WALLET API");
  console.log("----------------------------------------");
  console.log(`Server: http://127.0.0.1:${PORT}`);
  console.log(`Health: http://127.0.0.1:${PORT}/api/health`);
  console.log("Status: Server yana aiki.");
  console.log("Danna Ctrl + C domin dakatar da shi.");
});

server.on("error", (err) => {
  console.error("An kasa fara server:", err.message);
  process.exitCode = 1;
});
