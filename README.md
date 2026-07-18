# LeakShield Pro

LeakShield Pro is a DevSecOps secret detection system for scanning pasted code, configuration, CI logs, and repository snippets for leaked credentials. It combines modular regex rules, context-aware threat scoring, rule-based explanations, PostgreSQL persistence, Redis caching, and a modern React dashboard.

## Architecture

```text
User
  -> React/Tailwind Dashboard
  -> FastAPI REST API
  -> Scan Service
  -> Detection Engine
  -> Risk Engine
  -> Explanation Engine
  -> PostgreSQL + Redis
  -> JSON API Response
  -> Dashboard Results
```

## Tech Stack

- Backend: Python 3.11, FastAPI, SQLAlchemy Async, asyncpg
- Frontend: React, Vite, Tailwind CSS
- Database: PostgreSQL 16
- Cache: Redis 7
- Deployment: Docker Compose

The Vercel deployment uses the serverless API in `api/` and supports text, project-folder, website, and admin audit workflows. The Docker Compose deployment uses FastAPI and intentionally exposes text scanning only.

The admin API requires `ADMIN_EMAIL` and `ADMIN_PASSWORD`. Setting a separate high-entropy `ADMIN_SESSION_SECRET` is recommended; otherwise session signing is derived from the configured admin credentials. Private audit persistence additionally uses Vercel Blob when its storage variables are available.

## Run With Docker

```bash
cd leakshield-pro
docker compose up --build
```

Open:

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000/docs

Folder, website, and admin modes are hidden in Docker because they are implemented by the Vercel serverless API.

## Local Backend

```bash
cd leakshield-pro/backend
python -m venv .venv
. .venv/Scripts/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
cp .env.example .env
uvicorn app.main:app --reload
```

## Local Frontend

```bash
cd leakshield-pro/frontend
npm install
npm run dev
```

## API Example

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d "{\"content\":\"api_key='prod_live_ci_token_9f2b7c4a6d8e1f0a2b3c4d5e'\\npassword='ProdRootPass2026!'\",\"source_name\":\"deployment.env\"}"
```

## Sample Files

- `samples/sample_leak.txt`
- `samples/sample_response.json`
- `docs/report.md`
- `docs/architecture.md`
