import { useState } from 'react'
import { useAccount, useUsers, useUser, useUpdateUser } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, Toggle } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { User } from '../lib/api'

const columns: Column<User>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'email', title: 'Email', mono: true },
  { key: 'phone', title: 'Phone' },
  { key: 'owner', title: 'Org' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  {
    key: 'isAdmin', title: 'Admin',
    render: r => r.isAdmin ? <Badge color="green">Yes</Badge> : <Badge>No</Badge>,
  },
  {
    key: 'isForbidden', title: 'Status',
    render: r => r.isForbidden
      ? <Badge color="red">Forbidden</Badge>
      : r.isDeleted ? <Badge color="yellow">Deleted</Badge> : <Badge color="green">Active</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Users() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: users } = useUsers(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <UserDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Users" description="Manage user accounts across organizations." />
      <DataTable
        columns={columns}
        rows={users ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No users found"
      />
    </div>
  )
}

function UserDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: user } = useUser(owner, name)
  const mutation = useUpdateUser()
  const [draft, setDraft] = useState<Partial<User>>({})

  if (!user) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...user, ...draft }
  const set = <K extends keyof User>(key: K, val: User[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...user, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Email">
          <TextInput value={merged.email} onChange={e => set('email', e.target.value)} />
        </Field>
        <Field label="Phone">
          <TextInput value={merged.phone} onChange={e => set('phone', e.target.value)} />
        </Field>
        <Field label="Type">
          <TextInput value={merged.type} onChange={e => set('type', e.target.value)} />
        </Field>
        <Field label="Signup Application">
          <TextInput value={merged.signupApplication} readOnly />
        </Field>
        <Field label="Admin">
          <Toggle checked={merged.isAdmin} onChange={v => set('isAdmin', v)} />
        </Field>
        <Field label="Forbidden">
          <Toggle checked={merged.isForbidden} onChange={v => set('isForbidden', v)} />
        </Field>
      </div>
    </DetailPanel>
  )
}
