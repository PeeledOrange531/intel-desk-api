# Intel Desk — Sanctions Proxy

Lightweight Flask proxy that fetches, parses, and caches sanctions data from
four official government sources and serves it to the Intel Desk frontend.

## Lists covered
| ID    | Name                        | Authority       |
|-------|-----------------------------|-----------------|
| ofac  | SDN List                    | U.S. Treasury   |
| un    | Consolidated List           | UN Security Council |
| eu    | Consolidated Sanctions List | European Union  |
| uk    | OFSI Financial Sanctions    | HM Treasury     |

## Endpoints
| Endpoint        | Description                          |
|-----------------|--------------------------------------|
| `GET /health`   | Cache status for all lists           |
| `GET /search?q=NAME&lists=ofac,un,eu,uk&threshold=60` | Search all lists |
| `GET /list-status` | Per-list cache info for frontend |

## Deploy to Render
1. Push this folder to a GitHub repo (can be inside your main Intel Desk repo under `/sanctions-proxy`)
2. Go to render.com → New → Web Service → connect repo
3. Set root directory to `sanctions-proxy/` if inside a monorepo
4. Render auto-detects `render.yaml` — just click Deploy
5. Copy the `.onrender.com` URL into the frontend `PROXY_BASE` constant

## Environment variables
| Variable          | Default | Description                        |
|-------------------|---------|------------------------------------|
| `ALLOWED_ORIGINS` | `*`     | Comma-separated allowed CORS origins. Set to your domain in production e.g. `https://yourdomain.com` |
| `CACHE_TTL_SECONDS` | `21600` | How long to cache each list (default 6 hours) |

## Local dev
```bash
pip install -r requirements.txt
python app.py
# Server runs on http://localhost:5000
```

## Notes
- Lists are fetched lazily on first search, then cached in memory for 6 hours
- Render free tier spins down after inactivity — first search after spin-down
  will be slow (~30s) while lists are fetched. Consider a free uptime monitor
  (UptimeRobot) pinging `/health` every 10 minutes to keep it warm.
- OFAC SDN list is ~7MB XML, UN list ~2MB — parse takes 2–4s on first load
