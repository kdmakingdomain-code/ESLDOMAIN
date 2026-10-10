/*
 * Teacher Daisy Secure Classroom
 * - Passwords are stored as salted scrypt hashes, never sent to the browser.
 * - The server gates the dashboard and all content API routes behind a session.
 * - Only the teacher role can save shared content.
 *
 * Demo accounts are for local testing only. Replace them before deployment.
 */
"use strict";

const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const SESSION_SECRET = process.env.SESSION_SECRET;

if (IS_PRODUCTION && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
  console.error("Set SESSION_SECRET to a random value of at least 32 characters in production.");
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.warn("WARNING: using a development-only session secret. Set SESSION_SECRET before deployment.");
}

app.disable("x-powered-by");
// If deploying behind a trusted HTTPS reverse proxy, enable this setting:
// app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "100kb" }));

// Hardcoded demo accounts with salted scrypt hashes. These are backend-only.
// Teacher password: TeacherDemo!2026
// Student password: StudentDemo!2026
// Change these credentials before putting the app on the internet.
const USERS = {
  teacher: {
    username: "teacher",
    role: "teacher",
    salt: "ad65f99d986b1b8efba03f7bae229cab",
    hash: "bc87301cb5a799841552563f0c8af5ffdf992ba7d783423bf61a7919077c1f4403c32c4f5a6cb4a55f3d429e75db203a2a54437ac558ffff876a2cfe3a3be72a"
  },
  student: {
    username: "student",
    role: "student",
    salt: "aab9053b99d582b63b0eb0d2d517bf79",
    hash: "a78eb789b7fb5ec160a0b652853c5aabb5280177972ef1467be842815e1266901bdd39e4a9b7e5d588cecbcb607a99595dcdd3b9587f29c81311587777d41200"
  }
};

const DATA_DIR = path.join(__dirname, "data");
const CONTENT_FILE = path.join(DATA_DIR, "content.json");
fs.mkdirSync(DATA_DIR, { recursive: true });

const DEFAULT_CONTENT = {
  title: "Teacher Daisy's Classroom Board",
  body: "Welcome to class!\\n\\nCheck this board for announcements, homework, and reminders.\\n\\nTeacher: update this shared content after logging in as teacher."
};

function readContent() {
  try {
    return JSON.parse(fs.readFileSync(CONTENT_FILE, "utf8"));
  } catch {
    return DEFAULT_CONTENT;
  }
}
function writeContent(content) {
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(content, null, 2), { encoding: "utf8", mode: 0o600 });
}

// Local in-memory session store is fine for a local demo, not multi-instance production.
// For deployment, use a persistent session store (e.g. Redis or a database-backed store).
app.use(session({
  name: "teacher_daisy.sid",
  secret: SESSION_SECRET || "local-development-only-secret-change-before-deploy-2026",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: IS_PRODUCTION, // Production must use HTTPS.
    maxAge: 1000 * 60 * 60 * 4
  }
}));

// Basic in-memory rate limit for login attempts.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many login attempts. Please wait 15 minutes and try again."
});

app.use("/assets", express.static(path.join(__dirname, "public"), {
  index: false,
  dotfiles: "deny",
  maxAge: IS_PRODUCTION ? "1h" : 0
}));

function requireAuth(req, res, next) {
  if (!req.session.user) {
    if (req.accepts("html")) return res.redirect("/login");
    return res.status(401).json({ error: "Authentication required." });
  }
  next();
}
function requireTeacher(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Authentication required." });
  if (req.session.user.role !== "teacher") return res.status(403).json({ error: "Teacher permission required." });
  next();
}
function issueCsrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  return req.session.csrfToken;
}
function requireCsrf(req, res, next) {
  const supplied = req.get("x-csrf-token") || req.body?._csrf;
  const expected = req.session.csrfToken;
  const suppliedBuffer = Buffer.from(String(supplied || ""));
  const expectedBuffer = Buffer.from(String(expected || ""));
  if (!supplied || !expected || suppliedBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)) {
    return res.status(403).json({ error: "Invalid or expired security token. Refresh and try again." });
  }
  next();
}
function verifyPassword(password, user) {
  const actual = crypto.scryptSync(password, Buffer.from(user.salt, "hex"), 64);
  const expected = Buffer.from(user.hash, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

app.get("/", (req, res) => res.redirect(req.session.user ? "/classroom" : "/login"));

app.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/classroom");
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/login", loginLimiter, (req, res, next) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = USERS[username];
  // Use a generic error so the page does not reveal which username exists.
  if (!user || !verifyPassword(password, user)) {
    return res.status(401).send(loginPageWithError());
  }
  // Regenerate the session on login to mitigate session fixation.
  req.session.regenerate((err) => {
    if (err) return next(err);
    req.session.user = { username: user.username, role: user.role };
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    req.session.save((saveErr) => {
      if (saveErr) return next(saveErr);
      res.redirect("/classroom");
    });
  });
});

function loginPageWithError() {
  const html = fs.readFileSync(path.join(__dirname, "public", "login.html"), "utf8");
  return html.replace("<!-- LOGIN_ERROR -->",
    '<p class="error" role="alert">Incorrect username or password. Please try again.</p>');
}

app.get("/classroom", requireAuth, (req, res) => {
  const user = req.session.user;
  let html = fs.readFileSync(path.join(__dirname, "public", "classroom.html"), "utf8");
  const roleMarkup = user.role === "teacher"
    ? `<section class="editor card" aria-labelledby="editor-heading">
         <div class="section-title"><div><p class="eyebrow">TEACHER TOOLS</p><h2 id="editor-heading">Edit shared content</h2></div><span class="role-pill">Teacher editor</span></div>
         <label for="title-input">Board title</label>
         <input id="title-input" maxlength="120" />
         <label for="body-input">Announcements / lesson notes</label>
         <textarea id="body-input" rows="10" maxlength="20000" spellcheck="true"></textarea>
         <div class="editor-actions"><button id="save-button" class="button primary" type="button">Save changes</button><span id="save-status" class="muted" aria-live="polite"></span></div>
       </section>`
    : "";
  html = html
    .replace("<!-- ROLE_EDITOR -->", roleMarkup)
    .replaceAll("{{USERNAME}}", escapeHtml(user.username))
    .replaceAll("{{ROLE}}", escapeHtml(user.role))
    .replace("{{CSRF_TOKEN}}", escapeHtml(issueCsrfToken(req)));
  res.set("Cache-Control", "no-store");
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  res.send(html);
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

app.get("/api/content", requireAuth, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json(readContent());
});

app.post("/api/content", requireTeacher, requireCsrf, (req, res) => {
  const title = String(req.body.title || "").trim();
  const body = String(req.body.body || "").trim();
  if (!title || title.length > 120) return res.status(400).json({ error: "Title is required and must be 120 characters or fewer." });
  if (!body || body.length > 20000) return res.status(400).json({ error: "Content is required and must be 20,000 characters or fewer." });
  writeContent({ title, body });
  res.set("Cache-Control", "no-store");
  res.json({ ok: true, content: { title, body } });
});

app.post("/logout", requireAuth, requireCsrf, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie("teacher_daisy.sid", { httpOnly: true, sameSite: "strict", secure: IS_PRODUCTION });
    res.redirect("/login");
  });
});

// Friendly 404; private content is never served as a public static file.
app.use((req, res) => res.status(404).send("Not found"));

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).send("An unexpected server error occurred.");
});

app.listen(PORT, () => {
  console.log(`Teacher Daisy Secure Classroom is running at http://localhost:${PORT}`);
});
