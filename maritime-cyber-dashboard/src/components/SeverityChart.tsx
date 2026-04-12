'use client'

import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS: Record<string, string> = {
  Critical: '#dc2626',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6',
}

export default function SeverityChart({ incidents }: { incidents: { severity: string }[] }) {
  const counts: Record<string, number> = {}
  for (const inc of incidents) {
    counts[inc.severity] = (counts[inc.severity] ?? 0) + 1
  }
  const data = Object.entries(counts).map(([name, value]) => ({ name, value }))

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs uppercase tracking-wide mb-3">Incidents by Severity</div>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} innerRadius={35}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name] ?? '#6b7280'} />
            ))}
          </Pie>
          <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', color: '#fff' }} />
          <Legend formatter={(v) => <span className="text-gray-300 text-xs">{v}</span>} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
