import type { CSSProperties } from 'react'

const colors: Record<string, { bg: string; fg: string }> = {
  green:  { bg: '#052e16', fg: '#4ade80' },
  red:    { bg: '#450a0a', fg: '#f87171' },
  yellow: { bg: '#422006', fg: '#facc15' },
  blue:   { bg: '#172554', fg: '#60a5fa' },
  gray:   { bg: '#1c1c1c', fg: '#a3a3a3' },
}

export function Badge({ children, color = 'gray' }: { children: string; color?: keyof typeof colors }) {
  const c = colors[color] ?? colors.gray
  const style: CSSProperties = {
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 500,
    background: c.bg,
    color: c.fg,
  }
  return <span style={style}>{children}</span>
}
