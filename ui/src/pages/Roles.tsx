import { useState } from 'react'
import { useAccount, useRoles, useRole } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea, Toggle } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Role } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Role>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'owner', title: 'Org' },
  {
    key: 'users', title: 'Users',
    render: r => <span style={{ fontFamily: 'monospace' }}>{(r.users ?? []).length}</span>,
  },
  {
    key: 'isEnabled', title: 'Enabled',
    render: r => r.isEnabled ? <Badge color="green">Yes</Badge> : <Badge color="red">No</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Roles() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: roles } = useRoles(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <RoleDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Roles" description="Manage roles and their user/sub-role assignments." />
      <DataTable
        columns={columns}
        rows={roles ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No roles found"
      />
    </div>
  )
}

function RoleDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: role } = useRole(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (r: Role) => api.updateRole(r.owner, r.name, r),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['roles'] }),
  })
  const [draft, setDraft] = useState<Partial<Role>>({})

  if (!role) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...role, ...draft }
  const set = <K extends keyof Role>(key: K, val: Role[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...role, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Description">
          <TextInput value={merged.description} onChange={e => set('description', e.target.value)} />
        </Field>
        <Field label="Enabled">
          <Toggle checked={merged.isEnabled} onChange={v => set('isEnabled', v)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Users (one per line)">
          <TextArea
            value={(merged.users ?? []).join('\n')}
            onChange={e => set('users', e.target.value.split('\n').filter(Boolean))}
          />
        </Field>
        <Field label="Sub-roles (one per line)">
          <TextArea
            value={(merged.roles ?? []).join('\n')}
            onChange={e => set('roles', e.target.value.split('\n').filter(Boolean))}
          />
        </Field>
        <Field label="Domains (one per line)">
          <TextArea
            value={(merged.domains ?? []).join('\n')}
            onChange={e => set('domains', e.target.value.split('\n').filter(Boolean))}
          />
        </Field>
      </div>
    </DetailPanel>
  )
}
