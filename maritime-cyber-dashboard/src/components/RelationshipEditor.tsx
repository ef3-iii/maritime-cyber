'use client'

import { useState } from 'react'
import { getSupabaseBrowser } from '@/lib/supabase-browser'

interface Option { id: string; name: string }

interface Props {
  incidentId: string
  field: 'threat_group_id' | 'maritime_asset_id'
  label: string
  options: Option[]
  currentId: string | null
  currentName: string | null
}

export default function RelationshipEditor({
  incidentId, field, label, options, currentId, currentName,
}: Props) {
  const [editing, setEditing] = useState(false)
  const [selected, setSelected] = useState<string>(currentId ?? '')
  const [saving, setSaving] = useState(false)
  const [displayName, setDisplayName] = useState<string | null>(currentName)

  async function save() {
    setSaving(true)
    const supabase = getSupabaseBrowser()
    const value = selected === '' ? null : selected
    const { error } = await supabase
      .from('incidents')
      .update({ [field]: value })
      .eq('id', incidentId)

    if (!error) {
      const match = options.find(o => o.id === selected)
      setDisplayName(match?.name ?? null)
      setEditing(false)
    }
    setSaving(false)
  }

  if (!editing) {
    return (
      <div className="bg-gray-900 rounded-lg p-4">
        <div className="text-gray-400 text-xs uppercase tracking-wide mb-1">{label}</div>
        <div className="flex items-center justify-between gap-2">
          <span className="font-medium">{displayName ?? '—'}</span>
          <button
            onClick={() => setEditing(true)}
            className="text-xs text-blue-400 hover:text-blue-300 border border-blue-800 hover:border-blue-600 px-2 py-1 rounded transition-colors"
          >
            {displayName ? 'Change' : 'Link'}
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs uppercase tracking-wide mb-2">{label}</div>
      <select
        value={selected}
        onChange={e => setSelected(e.target.value)}
        className="w-full bg-gray-800 text-white rounded px-3 py-2 text-sm border border-gray-700 focus:border-blue-500 focus:outline-none mb-3"
      >
        <option value="">— None —</option>
        {options.map(o => (
          <option key={o.id} value={o.id}>{o.name}</option>
        ))}
      </select>
      <div className="flex gap-2">
        <button
          onClick={save}
          disabled={saving}
          className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-900 text-white text-xs font-semibold px-3 py-1.5 rounded transition-colors"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button
          onClick={() => { setEditing(false); setSelected(currentId ?? '') }}
          className="text-gray-400 hover:text-white text-xs px-3 py-1.5 rounded border border-gray-700 hover:border-gray-500 transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  )
}
