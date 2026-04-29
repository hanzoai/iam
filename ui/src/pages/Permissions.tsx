import { useState } from 'react'
import { useAccount, usePermissions } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea, Toggle } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Permission } from '../lib/api'
import { api } from '../lib/api'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Permission>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'resourceType', title: 'Resource Type' },
  {
    key: 'actions', title: 'Actions',
    render: r => (r.actions ?? []).map(a => <Badge key={a} color="blue">{a}</Badge>),
  },
  {
    key: 'effect', title: 'Effect',
    render: r => <Badge color={r.effect === 'Allow' ? 'green' : 'red'}>{r.effect}</Badge>,
  },
  { key: 'model', title: 'Model' },
  {
    key: 'state', title: 'State',
    render: r => <Badge color={r.state === 'Approved' ? 'green' : 'yellow'}>{r.state || 'Pending'}</Badge>,
  },
]

export function Permissions() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: perms } = usePermissions(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <PermDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Permissions" description="Access control permissions with resource types and actions." />
      <DataTable
        columns={columns}
        rows={perms ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No permissions found"
      />
    </div>
  )
}

function PermDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: perm } = useQuery({
    queryKey: ['permission', owner, name],
    queryFn: () => api.getPermission(owner, name).then(r => r.data),
  })
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (p: Permission) => api.updatePermission(p.owner, p.name, p),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['permissions'] }),
  })
  const [draft, setDraft] = useState<Partial<Permission>>({})

  if (!perm) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...perm, ...draft }
  const set = <K extends keyof Permission>(key: K, val: Permission[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...perm, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Model">
          <TextInput value={merged.model} onChange={e => set('model', e.target.value)} />
        </Field>
        <Field label="Adapter">
          <TextInput value={merged.adapter} onChange={e => set('adapter', e.target.value)} />
        </Field>
        <Field label="Resource Type">
          <TextInput value={merged.resourceType} onChange={e => set('resourceType', e.target.value)} />
        </Field>
        <Field label="Effect">
          <TextInput value={merged.effect} onChange={e => set('effect', e.target.value)} />
        </Field>
        <Field label="Enabled">
          <Toggle checked={merged.isEnabled} onChange={v => set('isEnabled', v)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Resources (one per line)">
          <TextArea
            value={(merged.resources ?? []).join('\n')}
            onChange={e => set('resources', e.target.value.split('\n').filter(Boolean))}
          />
        </Field>
        <Field label="Actions (one per line)">
          <TextArea
            value={(merged.actions ?? []).join('\n')}
            onChange={e => set('actions', e.target.value.split('\n').filter(Boolean))}
          />
        </Field>
      </div>
    </DetailPanel>
  )
}
