import { useAccount, useSessions, useDeleteSession } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import type { Column } from '../components/DataTable'
import type { Session } from '../lib/api'

export function Sessions() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: sessions } = useSessions(owner)
  const kill = useDeleteSession()

  const columns: Column<Session>[] = [
    { key: 'owner', title: 'Owner', render: r => <span style={{ fontWeight: 500 }}>{r.owner}</span> },
    { key: 'name', title: 'Name' },
    {
      key: 'sessionId', title: 'Session IDs',
      render: r => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>
        {(r.sessionId ?? []).length} active
      </span>,
    },
    {
      key: 'createdTime', title: 'Created',
      render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
    },
    {
      key: '_kill', title: '',
      render: r => (
        <button
          onClick={e => { e.stopPropagation(); kill.mutate(r) }}
          disabled={kill.isPending}
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
          Kill
        </button>
      ),
    },
  ]

  return (
    <div>
      <PageHeader title="Sessions" description="Active user sessions. Kill sessions to force re-authentication." />
      <DataTable
        columns={columns}
        rows={sessions ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        empty="No sessions found"
      />
    </div>
  )
}
