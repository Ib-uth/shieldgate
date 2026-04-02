# ShieldGate downstream (Vercel)

Minimal API that satisfies ShieldGate’s **`DOWNSTREAM_URL`** contract:

| Route | Used for |
|-------|----------|
| `GET /health` | Gateway health probe (`check_downstream_health`) — must return **200**. |
| `GET /api/v1/ping` | Reached from the gateway as `GET /proxy/ping` (default `DOWNSTREAM_API_PREFIX=api/v1`). |

## Local run

```bash
cd apps/downstream-vercel
npm install
npm run dev
```

- http://localhost:3001/health  
- http://localhost:3001/api/v1/ping  

## Deploy on Vercel

1. Import this Git repo in Vercel.
2. Set **Root Directory** to `apps/downstream-vercel`.
3. Deploy. Copy the production URL, e.g. `https://your-app.vercel.app`.

## Configure the gateway

On the ShieldGate gateway (e.g. Render):

```bash
DOWNSTREAM_URL=https://your-app.vercel.app
```

No trailing slash, no path. Redeploy the gateway.

## Smoke tests

```bash
curl -sSf https://your-app.vercel.app/health
curl -sSf https://your-app.vercel.app/api/v1/ping
```

Through the gateway (JWT required):

```bash
curl -sSf -H "Authorization: Bearer <access_token>" \
  https://your-gateway-host/proxy/ping
```

## Notes

- Cold starts on Vercel can add latency on the first request after idle.
- Do **not** set `DOWNSTREAM_URL` to the gateway’s own URL.
