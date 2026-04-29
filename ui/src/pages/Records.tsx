import { useAccount, useRecords } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { AuditRecord } from '../lib/api'

const columns: Column<AuditRecord>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  {
    key: 'method', title: 'Method',
    render: r => {
      const color = r.method === 'GET' ? 'green' : r.method === 'POST' ? 'blue' : r.method === 'DELETE' ? 'red' : 'gray'
      return <Badge color={color}>{r.method}</Badge>
    },
  },
  {
    key: 'requestUri', title: 'Request URI', mono: true,
    render: r => (
      <span style={{ fontFamily: 'monospace', fontSize: 11 }}>
        {(r.requestUri ?? '').length > 50 ? r.requestUri.slice(0, 50) + '...' : r.requestUri}
      </span>
    ),
  },
  { key: 'user', title: 'User' },
  { key: 'clientIp', title: 'Client IP', mono: true },
  {
    key: 'isTriggered', title: 'Triggered',
    render: r => r.isTriggered ? <Badge color="green">Yes</Badge> : <Badge>No</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Records() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: records } = useRecords(owner)

  return (
    <div>
      <PageHeader title="Records" description="API request audit log." />
      <DataTable
        columns={columns}
        rows={records ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        empty="No records found"
      />
    </div>
  )
}
