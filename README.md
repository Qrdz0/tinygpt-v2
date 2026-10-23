# tinygpt

A private, local-first AI chat interface built with Node.js and Ollama — your conversations never leave your machine.

## Features

- **Secure login system** — register/login with bcrypt-hashed passwords (10 rounds) and `express-session` sessions; includes email password-reset flows with single-use, expiring tokens.
- **SQLite chat history** — every conversation is stored locally in a SQLite database (`better-sqlite3`), per user.
- **Markdown + code highlighting** — messages render with `marked`, `highlight.js`, and DOMPurify (sanitized HTML), in a GitHub-dark theme.
- **Sleek premium UI** — dark, polished chat interface with model picker, streaming responses, and separate pages for login, forgot/reset password, privacy, and terms.
- **Ollama proxy** — the backend streams chat from a local Ollama instance; the browser never talks to Ollama directly.
- **100% local** — no cloud APIs, no telemetry; data never leaves the machine.

## Tech Stack

- **Node.js** + **Express** — HTTP server and API
- **express-session** — session management
- **bcrypt** — password hashing
- **better-sqlite3** — local chat/user database
- **nodemailer** — password-reset emails (SMTP, optional)
- **[Ollama](https://ollama.com)** — local LLM inference (default `http://localhost:11434`)
- **marked** + **highlight.js** + **DOMPurify** — Markdown rendering with sanitized HTML

## How to run it locally

1. **Install [Ollama](https://ollama.com/download)**, start it, and pull a model:

   ```bash
   ollama pull qwen2.5-coder:7b
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Start the server:**

   ```bash
   npm start
   ```

4. Open **http://localhost:3000**, create an account, and start chatting.

Optional environment variables: `PORT` (default `3000`), `OLLAMA_URL`, `APP_BASE_URL`, `SESSION_SECRET`, and SMTP settings for password-reset emails. The SQLite database is created automatically on first run.

---

Built by [Qrdz0](https://github.com/Qrdz0). I vibecode for fun, but I always try to learn a bit.
