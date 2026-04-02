export default function Home() {
  return (
    <main style={{ fontFamily: 'system-ui', padding: '2rem' }}>
      <h1>ShieldGate downstream</h1>
      <p>
        Use <code>GET /health</code> and <code>GET /api/v1/ping</code>. Deploy to
        Vercel and set <code>DOWNSTREAM_URL</code> on the gateway to this app&apos;s
        origin.
      </p>
    </main>
  );
}
