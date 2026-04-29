import { useAccount, useVerifications } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Verification } from '../lib/api'

const columns: Column<Verification>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  { key: 'provider', title: 'Provider' },
  { key: 'receiver', title: 'Receiver' },
  {
    key: 'isUsed', title: 'Used',
    render: r => r.isUsed ? <Badge color="green">Yes</Badge> : <Badge color="yellow">No</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Verifications() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: verifications } = useVerifications(owner)

  return (
    <div>
      <PageHeader title="Verifications" description="Email and phone verification records." />
      <DataTable
        columns={columns}
        rows={verifications ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        empty="No verifications found"
      />
    </div>
  )
}
