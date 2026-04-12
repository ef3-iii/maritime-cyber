'use client'

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

export default function SectorChart({ incidents }: { incidents: { sector: string }[] }) {
  const counts: Record<string, number> = {}
  for (const inc of incidents) {
    counts[inc.sector] = (counts[inc.sector] ?? 0) + 1
  }
  const data = Object.entries(counts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs uppercase tracking-wide mb-3">Incidents by Sector</div>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
          <XAxis type="number" allowDecimals={false} tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis type="category" dataKey="name" tick={{ fill: '#d1d5db', fontSize: 11 }} axisLine={false} tickLine={false} width={110} />
          <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', color: '#fff' }} cursor={{ fill: '#ffffff10' }} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]}>
            {data.map((_, i) => (
              <Cell key={i} fill={`hsl(${210 - i * 15}, 70%, 55%)`} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
