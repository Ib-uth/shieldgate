import { NextResponse } from 'next/server';

/** Called via ShieldGate as GET /proxy/ping → {DOWNSTREAM_URL}/api/v1/ping */
export async function GET() {
  return NextResponse.json({ message: 'pong' });
}
