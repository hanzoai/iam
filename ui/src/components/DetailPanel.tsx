import type { CSSProperties, ReactNode } from 'react'

const panel: CSSProperties = {
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 8,
  padding: 20,
}

const header: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  marginBottom: 16,
}

const title: CSSProperties = { fontSize: 16, fontWeight: 600, color: '#fff' }

const btnStyle: CSSProperties = {
  padding: '6px 16px',
  borderRadius: 6,
  border: 'none',
  fontSize: 13,
  fontWeight: 500,
  cursor: 'pointer',
}

export function DetailPanel({
  name,
  onBack,
  onSave,
  saving,
  children,
}: {
  name: string
  onBack: () => void
  onSave?: () => void
  saving?: boolean
  children: ReactNode
}) {
  return (
    <div style={panel}>
      <div style={header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={onBack}
            style={{ ...btnStyle, background: '#262626', color: '#e5e5e5' }}
          >
            Back
          </button>
          <span style={title}>{name}</span>
        </div>
        {onSave && (
          <button
            onClick={onSave}
            disabled={saving}
            style={{ ...btnStyle, background: '#fd4444', color: '#fff', opacity: saving ? 0.6 : 1 }}
          >
            {saving ? 'Saving...' : 'Save'}
          </button>
        )}
      </div>
      {children}
    </div>
  )
}
