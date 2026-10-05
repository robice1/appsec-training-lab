import express, { NextFunction, Request, Response } from "express";
import session from "express-session";
import multer from "multer";
import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { Pool } from "pg";

const app = express();
const port = Number(process.env.PORT ?? 3000);
const uploadDirectory = path.join(process.cwd(), "uploads");
const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ??
    "postgres://vulnapp:vulnapp@localhost:5432/vulnapp"
});

fs.mkdirSync(uploadDirectory, { recursive: true });

app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(process.cwd(), "public")));
app.use("/uploads", express.static(uploadDirectory));

// Training misconfiguration: wildcard CORS, a predictable session secret, and
// cookies without secure or sameSite flags are intentional scanner targets.
app.use((_req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  next();
});
app.use(
  session({
    secret: process.env.SESSION_SECRET ?? "training-only-secret",
    resave: false,
    saveUninitialized: true
  })
);

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, uploadDirectory),
    filename: (_req, file, callback) => callback(null, file.originalname)
  }),
  limits: { fileSize: 4 * 1024 * 1024 }
});

async function initializeDatabase(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS articles (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      author TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS documents (
      id SERIAL PRIMARY KEY,
      owner TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL
    );
    INSERT INTO articles (title, body)
      SELECT 'Deployment notes', 'The staging checklist and release timeline.'
      WHERE NOT EXISTS (SELECT 1 FROM articles);
    INSERT INTO articles (title, body)
      SELECT 'Workshop guide', 'A practical guide to the security lab.'
      WHERE NOT EXISTS (SELECT 1 FROM articles WHERE title = 'Workshop guide');
    INSERT INTO users (username, password, role) VALUES
      ('alice', 'alice123', 'user'),
      ('admin', 'admin123', 'admin')
      ON CONFLICT (username) DO NOTHING;
    INSERT INTO documents (owner, title, body)
      SELECT 'alice', 'Alice project notes', 'Draft notes for the sample project.'
      WHERE NOT EXISTS (SELECT 1 FROM documents WHERE title = 'Alice project notes');
    INSERT INTO documents (owner, title, body)
      SELECT 'admin', 'Internal roadmap', 'A demo-only roadmap document.'
      WHERE NOT EXISTS (SELECT 1 FROM documents WHERE title = 'Internal roadmap');
  `);
}

app.get("/", async (_req, res, next) => {
  try {
    const [{ rows: articles }, { rows: comments }, { rows: documents }] =
      await Promise.all([
        pool.query("SELECT id, title, body FROM articles ORDER BY id"),
        pool.query(
          "SELECT id, author, body, created_at FROM comments ORDER BY id DESC LIMIT 8"
        ),
        pool.query("SELECT id, owner, title FROM documents ORDER BY id")
      ]);
    res.render("index", {
      articles,
      comments,
      documents,
      user: (_req.session as TrainingSession).username
    });
  } catch (error) {
    next(error);
  }
});

app.get("/search", async (req, res, next) => {
  try {
    const term = String(req.query.q ?? "");
    // SQL injection training target: user input is interpolated into SQL.
    const { rows } = await pool.query(
      `SELECT id, title, body FROM articles WHERE title ILIKE '%${term}%' OR body ILIKE '%${term}%'`
    );
    res.render("search", { term, articles: rows });
  } catch (error) {
    next(error);
  }
});

app.get("/greet", (req, res) => {
  // Reflected XSS training target: the view outputs this value without escaping.
  res.render("greet", { name: String(req.query.name ?? "visitor") });
});

app.get("/comments", async (_req, res, next) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, author, body, created_at FROM comments ORDER BY id DESC"
    );
    res.render("comments", { comments: rows });
  } catch (error) {
    next(error);
  }
});

app.post("/comments", async (req, res, next) => {
  try {
    const author = String(req.body.author ?? "anonymous").slice(0, 80);
    const body = String(req.body.body ?? "");
    await pool.query("INSERT INTO comments (author, body) VALUES ($1, $2)", [
      author,
      body
    ]);
    res.redirect("/comments");
  } catch (error) {
    next(error);
  }
});

app.get("/api/diagnostics", (req, res) => {
  const message = String(req.query.message ?? "training lab");
  // Command injection training target: the query value reaches a shell command.
  exec(`echo ${message}`, { timeout: 3000, maxBuffer: 64 * 1024 }, (error, stdout, stderr) => {
    if (error) {
      res.status(400).json({ error: error.message, stderr });
      return;
    }
    res.json({ output: stdout.trim() });
  });
});

app.get("/api/files", (req, res, next) => {
  const requestedPath = String(req.query.path ?? "");
  // Path traversal and insecure file handling training target.
  const filePath = path.join(uploadDirectory, requestedPath);
  fs.readFile(filePath, (error, contents) => {
    if (error) {
      next(error);
      return;
    }
    res.type("text/plain").send(contents);
  });
});

app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    res.status(400).send("Choose a file to upload.");
    return;
  }
  res.redirect(`/?uploaded=${encodeURIComponent(req.file.originalname)}`);
});

app.get("/api/documents/:id", async (req, res, next) => {
  try {
    // IDOR training target: the document ID is used without checking its owner.
    const { rows } = await pool.query(
      "SELECT id, owner, title, body FROM documents WHERE id = $1",
      [req.params.id]
    );
    if (rows.length === 0) {
      res.status(404).json({ error: "Document not found" });
      return;
    }
    res.json(rows[0]);
  } catch (error) {
    next(error);
  }
});

app.get("/api/fetch", async (req, res) => {
  const target = String(req.query.url ?? "");
  try {
    // SSRF training target: the caller controls the URL fetched by the server.
    const response = await fetch(target, { signal: AbortSignal.timeout(5000) });
    const body = (await response.text()).slice(0, 4096);
    res.json({ status: response.status, body });
  } catch (error) {
    res.status(502).json({
      error: error instanceof Error ? error.message : String(error)
    });
  }
});

app.post("/login", async (req, res, next) => {
  try {
    const username = String(req.body.username ?? "");
    const password = String(req.body.password ?? "");
    // Intentionally weak authentication: plaintext passwords and SQL injection.
    const { rows } = await pool.query(
      `SELECT id, username, role FROM users WHERE username = '${username}' AND password = '${password}'`
    );
    if (rows.length === 0) {
      res.status(401).render("message", {
        title: "Sign-in failed",
        message: "The demo account could not be authenticated."
      });
      return;
    }
    (req.session as TrainingSession).username = rows[0].username;
    (req.session as TrainingSession).role = rows[0].role;
    res.redirect("/");
  } catch (error) {
    next(error);
  }
});

app.get("/admin", async (_req, res, next) => {
  try {
    // Insecure authorization training target: no session or role check is done.
    const [{ rows: users }, { rows: documents }] = await Promise.all([
      pool.query("SELECT id, username, role FROM users ORDER BY id"),
      pool.query("SELECT id, owner, title FROM documents ORDER BY id")
    ]);
    res.render("admin", { users, documents });
  } catch (error) {
    next(error);
  }
});

app.get("/debug/config", (_req, res) => {
  // Security misconfiguration target: exposes runtime configuration for the lab.
  res.json({
    environment: process.env.NODE_ENV ?? "development",
    port,
    database: "PostgreSQL training database",
    sessionSecretConfigured: Boolean(process.env.SESSION_SECRET)
  });
});

app.post("/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) {
      next(error);
      return;
    }
    res.redirect("/");
  });
});

app.use(
  (error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    // Development-style stack traces are intentionally exposed for misconfiguration testing.
    res.status(500).type("text/plain").send(message);
  }
);

interface TrainingSession extends session.Session {
  username?: string;
  role?: string;
}

initializeDatabase()
  .then(() => {
    app.listen(port, "0.0.0.0", () => {
      console.log(`AppSec Training Lab listening on http://localhost:${port}`);
    });
  })
  .catch((error: unknown) => {
    console.error("Database initialization failed:", error);
    process.exitCode = 1;
  });
