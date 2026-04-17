import { useAccount, useInvitations } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Invitation } from '../lib/api'

const stateColor: Record<string, 'green' | 'yellow' | 'red' | 'gray'> = {
  Accepted: 'green',
  Pending: 'yellow',
  Expired: 'red',
}

const columns: Column<Invitation>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'sender', title: 'Sender' },
  { key: 'recipient', title: 'Recipient' },
  { key: 'application', title: 'Application' },
  {
    key: 'state', title: 'State',
    render: r => <Badge color={stateColor[r.state] ?? 'gray'}>{r.state || 'Pending'}</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Invitations() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: invitations } = useInvitations(owner)

  return (
    <div>
      <PageHeader title="Invitations" description="User invitations sent and received." />
      <DataTable
        columns={columns}
        rows={invitations ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        empty="No invitations found"
      />
    </div>
  )
}
