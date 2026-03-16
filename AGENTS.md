# AGENTS.md

## Cursor Cloud specific instructions

This is a Python Flask system monitoring dashboard (Omni-Server-Status). See `README.md` for full deployment docs.

### Architecture

- **Server** (`server/server.py`): Flask web app on port 5000. Uses SQLite (auto-created `server/monitor.db`). Default admin credentials: `admin`/`admin`.
- **Client** (`client/client.py`): Daemon that collects system metrics (CPU, memory, disk, GPU) and POSTs to server's `/report` endpoint every 60s.

### Running in dev

```bash
# Server (from repo root)
cd server && venv/bin/python server.py
# Client (from repo root, in a separate terminal)
cd client && venv/bin/python client.py
# Client one-shot test
cd client && venv/bin/python client.py --test
```

Dashboard: http://localhost:5000

### Gotchas

- The client requires `/var/log/system-monitor/` and `/etc/system-monitor/` directories to exist with write permissions. Create them with `sudo mkdir -p /var/log/system-monitor /etc/system-monitor && sudo chmod 777 /var/log/system-monitor /etc/system-monitor` before first run.
- The server gracefully falls back to a local `server.log` if `/var/log/system-monitor/` is not writable, but the client does not have this fallback.
- No linting tools or automated test suites are configured in this project.
- No Docker, no external databases, no external services required. Fully self-contained.
