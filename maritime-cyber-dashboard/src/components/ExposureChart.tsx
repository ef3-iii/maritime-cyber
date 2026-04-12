'use client'

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const color = (score: number) => {
  if (score >= 75) return '#ef4444'
  if (score >= 50) return '#f97316'
  if (score >= 25) return '#eab308'
  return '#22c55e'
}

export default function ExposureChart({ assets }: { assets: { name: string; exposure_score: number }[] }) {
  const data = [...assets].sort((a, b) => b.exposure_score - a.exposure_score)

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs uppercase tracking-wide mb-3">Asset Exposure Scores</div>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 32 }}>
          <XAxis type="number" domain={[0, 100]} tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis type="category" dataKey="name" tick={{ fill: '#d1d5db', fontSize: 11 }} axisLine={false} tickLine={false} width={160} />
          <Tooltip contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', color: '#fff' }} cursor={{ fill: '#ffffff10' }} formatter={(v) => [`${v} / 100`, 'Exposure']} />
          <Bar dataKey="exposure_score" radius={[0, 4, 4, 0]}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={color(entry.exposure_score)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
