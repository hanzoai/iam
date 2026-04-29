import type { CSSProperties, ReactNode } from 'react'

export interface Column<T> {
  key: string
  title: string
  render?: (row: T) => ReactNode
  mono?: boolean
  width?: number | string
}

const thStyle: CSSProperties = {
  padding: '8px 12px',
  textAlign: 'left',
  color: '#737373',
  fontWeight: 500,
  fontSize: 12,
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
}

const tdStyle: CSSProperties = {
  padding: '8px 12px',
  fontSize: 13,
}

interface Props<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  onRowClick?: (row: T) => void
  empty?: string
}

export function DataTable<T>({ columns, rows, rowKey, onRowClick, empty }: Props<T>) {
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
      <thead>
        <tr style={{ borderBottom: '1px solid #262626' }}>
          {columns.map(c => (
            <th key={c.key} style={{ ...thStyle, width: c.width }}>{c.title}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map(row => (
          <tr
            key={rowKey(row)}
            onClick={() => onRowClick?.(row)}
            style={{
              borderBottom: '1px solid #171717',
              cursor: onRowClick ? 'pointer' : undefined,
            }}
          >
            {columns.map(c => (
              <td
                key={c.key}
                style={{
                  ...tdStyle,
                  fontFamily: c.mono ? 'monospace' : undefined,
                }}
              >
                {c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? '')}
              </td>
            ))}
          </tr>
        ))}
        {rows.length === 0 && (
          <tr>
            <td colSpan={columns.length} style={{ padding: '16px 12px', color: '#525252', fontSize: 13 }}>
              {empty ?? 'No data'}
            </td>
          </tr>
        )}
      </tbody>
    </table>
  )
}
