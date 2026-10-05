# AppSec Training Lab

AppSec Training Lab is a small, intentionally vulnerable Node.js and TypeScript web application for local security testing and AppSec education. It combines an Express server, EJS views, a PostgreSQL database, and a Docker Compose setup. Its vulnerabilities are deliberate, easy to locate, and suitable for exercising static and dynamic scanners.

> **Safety:** This app is intentionally insecure. Run it only in a disposable environment you control. Do not expose it to the public internet or use real data or credentials. The vulnerable app and database share an internal Docker network and cannot make outbound connections to external services. A fixed-route Nginx gateway publishes the app to your local host. The SSRF exercise can reach services on the internal training network.

## Run locally with Docker Compose

Requirements: Docker Desktop (or Docker Engine) and the Compose plugin.

```powershell
docker compose up --build
```

Open [http://localhost:3000](http://localhost:3000). The app waits for PostgreSQL to become healthy, then creates and seeds its sample tables on startup.

Stop the services with `Ctrl+C`, or run:

```powershell
docker compose down
```

To remove the lab's database and uploaded-file data as well:

```powershell
docker compose down --volumes
```

The only accounts are training fixtures: `alice` / `alice123` and `admin` / `admin123`. These are not real credentials.

## Optional: run the server directly

For development outside Compose, install Node.js 22 or later and have a local PostgreSQL instance available. Set `DATABASE_URL` to a disposable local database, then:

```powershell
npm install
$env:DATABASE_URL = "postgres://vulnapp:vulnapp@localhost:5432/vulnapp"
npm run dev
```

Direct local execution does not inherit Compose's network isolation. The SSRF and command-injection exercises can reach whatever the local process can access; prefer the Docker Compose environment for scanner testing.

## Training surface

The dashboard links to each exercise. Source comments call out the intentional sink and label the targets:

| Component | Example |
| --- | --- |
| SQL injection | `/search?q=...` and the `/login` query in `src/server.ts` |
| Reflected XSS | `/greet?name=...` |
| Stored XSS | Submit a comment at `/comments` |
| Command injection | `/api/diagnostics?message=...` |
| Path traversal | `/api/files?path=...` |
| Insecure file handling | Upload arbitrary files at `/upload`; files are also served from `/uploads` |
| IDOR | `/api/documents/1` and `/api/documents/2`, without owner checks |
| SSRF | `/api/fetch?url=http://app:3000/debug/config` |
| Weak authentication / authorization | Plaintext demo passwords, injectable login, and unauthenticated `/admin` exposing sample account/document records |
| Security misconfiguration | Wildcard CORS, a predictable session secret, permissive cookie settings, and exposed `/debug/config` |

The app uses only local services included in the Compose file. There are no real third-party integrations or production credentials. The gateway has a normal Docker bridge for host port publishing but only proxies requests to the app; it is not an outbound HTTP proxy.

## Scanner practice

Point authorized local scans at `http://localhost:3000`. For tools that scan container images, build the `appsec-training-lab` image locally with Compose. The repository intentionally includes multiple source-level and runtime findings; discovery depends on scanner configuration, scope, and rules.
