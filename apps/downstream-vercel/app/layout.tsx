import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'ShieldGate downstream',
  description: 'Minimal API for ShieldGate DOWNSTREAM_URL',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
