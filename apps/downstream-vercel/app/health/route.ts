import { NextResponse } from 'next/server';

/** Gateway probes GET {DOWNSTREAM_URL}/health — must return 200. */
export async function GET() {
  return NextResponse.json({ status: 'ok' });
}
