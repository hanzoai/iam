import type { CSSProperties } from 'react'

const h1: CSSProperties = { fontSize: 20, fontWeight: 600, color: '#fff' }
const sub: CSSProperties = { fontSize: 13, color: '#737373', marginTop: 4 }

export function PageHeader({ title, description }: { title: string; description?: string }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <h1 style={h1}>{title}</h1>
      {description && <p style={sub}>{description}</p>}
    </div>
  )
}
