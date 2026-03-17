import { useAccount, useTokens, useDeleteToken } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Token } from '../lib/api'

function mask(s: string): string {
  if (!s || s.length < 12) return s ?? ''
  return s.slice(0, 8) + '...' + s.slice(-4)
}

export function Tokens() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: tokens } = useTokens(owner)
  const revoke = useDeleteToken()

  const columns: Column<Token>[] = [
    { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
    { key: 'organization', title: 'Org' },
    { key: 'application', title: 'Application' },
    { key: 'user', title: 'User' },
    { key: 'accessToken', title: 'Access Token', mono: true, render: r => mask(r.accessToken) },
    { key: 'scope', title: 'Scope' },
    {
      key: 'expiresIn', title: 'Expires In',
      render: r => <span style={{ fontFamily: 'monospace' }}>{r.expiresIn}s</span>,
    },
    {
      key: 'createdTime', title: 'Created',
      render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
    },
    {
      key: '_revoke', title: '',
      render: r => (
        <button
          onClick={e => { e.stopPropagation(); revoke.mutate(r) }}
          disabled={revoke.isPending}
          style={{
            padding: '3px 10px',
            borderRadius: 4,
            border: '1px solid #450a0a',
            background: 'transparent',
            color: '#f87171',
            fontSize: 11,
            cursor: 'pointer',
          }}
        >
          Revoke
        </button>
      ),
    },
  ]

  return (
    <div>
      <PageHeader title="Tokens" description="Active OAuth tokens. Revoke individual tokens as needed." />
      <DataTable
        columns={columns}
        rows={tokens ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        empty="No tokens found"
      />
    </div>
  )
}
