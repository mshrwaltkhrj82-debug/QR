const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const QRCode = require("qrcode");
const { OAuth2Client } = require("google-auth-library");

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const STUDENT_DOMAIN = (process.env.STUDENT_DOMAIN || "student.uomosul.edu.iq").toLowerCase();
const INSTRUCTORS = (process.env.INSTRUCTOR_EMAILS || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const DEV_LOGIN = process.env.DEV_LOGIN === "true";
const IS_PROD = process.env.NODE_ENV === "production";
const WINDOW_MS = 20000; // الرمز يتغيّر كل 20 ثانية

// ---------- قاعدة البيانات ----------
const db = new Database("attendance.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS students(email TEXT PRIMARY KEY, name TEXT, student_no TEXT);
CREATE TABLE IF NOT EXISTS courses(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, instructor_email TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrollments(course_id INTEGER, student_email TEXT, PRIMARY KEY(course_id, student_email));
CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY AUTOINCREMENT, course_id INTEGER NOT NULL, secret TEXT NOT NULL, opened_at INTEGER NOT NULL, closed_at INTEGER);
CREATE TABLE IF NOT EXISTS attendance(session_id INTEGER, student_email TEXT, ts INTEGER NOT NULL, PRIMARY KEY(session_id, student_email));
`);

// ---------- أدوات ----------
const roleOf = email =>
  INSTRUCTORS.includes(email) ? "instructor" :
  email.endsWith("@" + STUDENT_DOMAIN) ? "student" : null;

const curWindow = () => Math.floor(Date.now() / WINDOW_MS);
const tokenFor = (secret, w) =>
  crypto.createHmac("sha256", secret).update(String(w)).digest("hex").slice(0, 16);
const safeEq = (a, b) =>
  a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

const parseCsv = text =>
  text.replace(/^\uFEFF/, "").split(/\r?\n/)
    .map(l => l.split(",").map(x => x.trim())).filter(r => r[0]);

const csvCell = v => {
  let t = String(v ?? "");
  if (/^[=+\-@]/.test(t)) t = "'" + t; // منع حقن الصيغ في Excel
  return `"${t.replace(/"/g, '""')}"`;
};

// ---------- التطبيق ----------
const app = express();
if (IS_PROD) app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: IS_PROD, maxAge: 12 * 3600 * 1000 },
}));
app.use(express.static("public"));

const need = role => (req, res, next) =>
  req.session.email && req.session.role === role
    ? next() : res.status(401).json({ error: "غير مصرّح" });

function startSession(req, res, email, name) {
  email = String(email || "").toLowerCase();
  const role = roleOf(email);
  if (!role) return res.status(403).json({ error: "يُسمح فقط بالإيميل الجامعي" });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "خطأ في الخادم" });
    req.session.email = email;
    req.session.role = role;
    res.json({ email, role, name: name || "" });
  });
}

// ---------- تسجيل الدخول ----------
const gclient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

app.get("/api/config", (req, res) =>
  res.json({ googleClientId: GOOGLE_CLIENT_ID, devLogin: DEV_LOGIN }));

app.post("/api/login/google", async (req, res) => {
  if (!gclient) return res.status(404).json({ error: "Google غير مفعّل" });
  try {
    const ticket = await gclient.verifyIdToken({
      idToken: String(req.body.credential || ""), audience: GOOGLE_CLIENT_ID,
    });
    const p = ticket.getPayload();
    if (!p.email_verified) return res.status(403).json({ error: "الإيميل غير موثّق" });
    startSession(req, res, p.email, p.name);
  } catch {
    res.status(401).json({ error: "فشل التحقق من حساب Google" });
  }
});

app.post("/api/login/dev", (req, res) => {
  if (!DEV_LOGIN || IS_PROD) return res.status(404).json({ error: "غير متاح" });
  startSession(req, res, req.body.email, "");
});

app.get("/api/me", (req, res) =>
  req.session.email
    ? res.json({ email: req.session.email, role: req.session.role })
    : res.status(401).json({ error: "لم تسجّل الدخول" }));

app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

// ---------- المحاضر: المقررات ----------
app.post("/api/courses", need("instructor"), (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 100);
  if (!name) return res.status(400).json({ error: "اكتب اسم المقرر" });
  const r = db.prepare("INSERT INTO courses(name, instructor_email) VALUES(?,?)")
    .run(name, req.session.email);
  res.json({ id: r.lastInsertRowid });
});

app.get("/api/courses", need("instructor"), (req, res) => {
  res.json(db.prepare(`
    SELECT c.id, c.name,
      (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) AS enrolled
    FROM courses c WHERE c.instructor_email = ? ORDER BY c.id DESC`).all(req.session.email));
});

function ownedCourse(req, res) {
  const c = db.prepare("SELECT * FROM courses WHERE id = ? AND instructor_email = ?")
    .get(+req.params.id, req.session.email);
  if (!c) res.status(404).json({ error: "المقرر غير موجود" });
  return c;
}

// CSV: email,name,student_no
app.post("/api/courses/:id/import", need("instructor"), (req, res) => {
  const course = ownedCourse(req, res); if (!course) return;
  const rows = parseCsv(String(req.body.csv || ""));
  const upsert = db.prepare(`INSERT INTO students VALUES(?,?,?)
    ON CONFLICT(email) DO UPDATE SET name = excluded.name, student_no = excluded.student_no`);
  const enroll = db.prepare("INSERT OR IGNORE INTO enrollments VALUES(?,?)");
  let imported = 0, skipped = 0;
  db.transaction(() => {
    for (const [email, name, no] of rows) {
      const e = (email || "").toLowerCase();
      if (!e.includes("@")) continue; // سطر العناوين
      if (!e.endsWith("@" + STUDENT_DOMAIN)) { skipped++; continue; }
      upsert.run(e, name || "", no || "");
      enroll.run(course.id, e);
      imported++;
    }
  })();
  res.json({ imported, skipped });
});

// ---------- المحاضر: الجلسات ----------
app.post("/api/courses/:id/sessions", need("instructor"), (req, res) => {
  const course = ownedCourse(req, res); if (!course) return;
  db.prepare("UPDATE sessions SET closed_at = ? WHERE course_id = ? AND closed_at IS NULL")
    .run(Date.now(), course.id);
  const r = db.prepare("INSERT INTO sessions(course_id, secret, opened_at) VALUES(?,?,?)")
    .run(course.id, crypto.randomBytes(32).toString("hex"), Date.now());
  res.json({ id: r.lastInsertRowid });
});

function ownedSession(req, res) {
  const s = db.prepare(`
    SELECT s.*, c.name AS course FROM sessions s JOIN courses c ON c.id = s.course_id
    WHERE s.id = ? AND c.instructor_email = ?`).get(+req.params.id, req.session.email);
  if (!s) res.status(404).json({ error: "المحاضرة غير موجودة" });
  return s;
}

app.post("/api/sessions/:id/close", need("instructor"), (req, res) => {
  const s = ownedSession(req, res); if (!s) return;
  db.prepare("UPDATE sessions SET closed_at = ? WHERE id = ? AND closed_at IS NULL")
    .run(Date.now(), s.id);
  res.json({ ok: true });
});

app.get("/api/sessions/:id/qr", need("instructor"), async (req, res) => {
  const s = ownedSession(req, res); if (!s) return;
  if (s.closed_at) return res.status(400).json({ error: "المحاضرة مغلقة" });
  const url = `${BASE_URL}/?s=${s.id}&t=${tokenFor(s.secret, curWindow())}`;
  res.json({ dataUrl: await QRCode.toDataURL(url, { width: 420, margin: 1 }) });
});

app.get("/api/sessions/:id/attendance", need("instructor"), (req, res) => {
  const s = ownedSession(req, res); if (!s) return;
  const present = db.prepare(`
    SELECT a.student_email AS email, st.name, a.ts FROM attendance a
    LEFT JOIN students st ON st.email = a.student_email
    WHERE a.session_id = ? ORDER BY a.ts DESC`).all(s.id);
  const enrolled = db.prepare("SELECT COUNT(*) AS n FROM enrollments WHERE course_id = ?")
    .get(s.course_id).n;
  res.json({ present, enrolled });
});

app.get("/api/sessions/:id/export.csv", need("instructor"), (req, res) => {
  const s = ownedSession(req, res); if (!s) return;
  const rows = db.prepare(`
    SELECT st.student_no, st.name, e.student_email AS email, a.ts
    FROM enrollments e
    LEFT JOIN students st ON st.email = e.student_email
    LEFT JOIN attendance a ON a.session_id = ? AND a.student_email = e.student_email
    WHERE e.course_id = ? ORDER BY st.name`).all(s.id, s.course_id);
  const lines = [["الرقم الجامعي", "الاسم", "الإيميل", "الحالة", "وقت الحضور"].map(csvCell).join(",")];
  for (const r of rows) {
    lines.push([r.student_no, r.name, r.email, r.ts ? "حاضر" : "غائب",
      r.ts ? new Date(r.ts).toISOString() : ""].map(csvCell).join(","));
  }
  res.set({
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Disposition": `attachment; filename="attendance-${s.id}.csv"`,
  });
  res.send("\uFEFF" + lines.join("\r\n"));
});

// ---------- الطالب ----------
app.post("/api/attend", need("student"), (req, res) => {
  const sessionId = +req.body.sessionId;
  const token = String(req.body.token || "");
  const s = db.prepare(`
    SELECT s.*, c.name AS course FROM sessions s JOIN courses c ON c.id = s.course_id
    WHERE s.id = ?`).get(sessionId);
  if (!s || s.closed_at) return res.status(400).json({ error: "المحاضرة غير مفتوحة" });

  const w = curWindow();
  if (![w, w - 1].some(x => safeEq(tokenFor(s.secret, x), token)))
    return res.status(400).json({ error: "انتهت صلاحية الرمز، امسح الرمز الجديد من الشاشة" });

  const enrolled = db.prepare("SELECT 1 FROM enrollments WHERE course_id = ? AND student_email = ?")
    .get(s.course_id, req.session.email);
  if (!enrolled) return res.status(403).json({ error: "أنت غير مسجّل في هذا المقرر" });

  const r = db.prepare("INSERT OR IGNORE INTO attendance VALUES(?,?,?)")
    .run(s.id, req.session.email, Date.now());
  if (!r.changes) return res.status(409).json({ error: "سبق تسجيل حضورك في هذه المحاضرة" });
  res.json({ course: s.course });
});

app.get("/api/my-attendance", need("student"), (req, res) => {
  res.json(db.prepare(`
    SELECT c.name AS course, a.ts FROM attendance a
    JOIN sessions s ON s.id = a.session_id JOIN courses c ON c.id = s.course_id
    WHERE a.student_email = ? ORDER BY a.ts DESC LIMIT 100`).all(req.session.email));
});

app.listen(PORT, () => console.log(`Running on ${BASE_URL}`));
