import { useState } from 'react'
import { useAccount, useAdapters, useAdapter } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Adapter } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Adapter>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  { key: 'databaseType', title: 'DB Type' },
  { key: 'host', title: 'Host', mono: true },
  { key: 'table', title: 'Table', mono: true },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Adapters() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: adapters } = useAdapters(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <AdapterDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Adapters" description="Policy storage adapters for access control rules." />
      <DataTable
        columns={columns}
        rows={adapters ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No adapters found"
      />
    </div>
  )
}

function AdapterDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: adapter } = useAdapter(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (a: Adapter) => api.updateAdapter(a.owner, a.name, a),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['adapters'] }),
  })
  const [draft, setDraft] = useState<Partial<Adapter>>({})

  if (!adapter) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...adapter, ...draft }
  const set = <K extends keyof Adapter>(key: K, val: Adapter[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...adapter, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Type">
          <TextInput value={merged.type} onChange={e => set('type', e.target.value)} />
        </Field>
        <Field label="Database Type">
          <TextInput value={merged.databaseType} onChange={e => set('databaseType', e.target.value)} />
        </Field>
        <Field label="Database">
          <TextInput value={merged.database} onChange={e => set('database', e.target.value)} />
        </Field>
        <Field label="Host">
          <TextInput value={merged.host} onChange={e => set('host', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Port">
          <TextInput type="number" value={merged.port} onChange={e => set('port', Number(e.target.value))} />
        </Field>
        <Field label="User">
          <TextInput value={merged.user} onChange={e => set('user', e.target.value)} />
        </Field>
        <Field label="Table">
          <TextInput value={merged.table} onChange={e => set('table', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
      </div>
    </DetailPanel>
  )
}
