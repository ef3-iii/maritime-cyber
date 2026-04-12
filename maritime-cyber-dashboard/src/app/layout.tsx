import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Maritime Cyber Dashboard',
  description: 'Maritime cybersecurity threat intelligence platform',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
