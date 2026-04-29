import { useState } from 'react'
import { useAccount, useGroups, useGroup } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Group } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Group>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'owner', title: 'Org' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type || 'default'}</Badge> },
  {
    key: 'users', title: 'Users',
    render: r => <span style={{ fontFamily: 'monospace' }}>{(r.users ?? []).length}</span>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Groups() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: groups } = useGroups(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <GroupDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Groups" description="User groups for bulk access control." />
      <DataTable
        columns={columns}
        rows={groups ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No groups found"
      />
    </div>
  )
}

function GroupDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: group } = useGroup(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (g: Group) => api.updateGroup(g.owner, g.name, g),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['groups'] }),
  })
  const [draft, setDraft] = useState<Partial<Group>>({})

  if (!group) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...group, ...draft }
  const set = <K extends keyof Group>(key: K, val: Group[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...group, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Type">
          <TextInput value={merged.type} onChange={e => set('type', e.target.value)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Users (one per line)">
          <TextArea
            value={(merged.users ?? []).join('\n')}
            onChange={e => set('users', e.target.value.split('\n').filter(Boolean))}
          />
        </Field>
      </div>
    </DetailPanel>
  )
}
