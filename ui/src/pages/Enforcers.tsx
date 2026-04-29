import { useState } from 'react'
import { useAccount, useEnforcers, useEnforcer } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import type { Column } from '../components/DataTable'
import type { Enforcer } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Enforcer>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'owner', title: 'Org' },
  { key: 'model', title: 'Model' },
  { key: 'adapter', title: 'Adapter' },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Enforcers() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: enforcers } = useEnforcers(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <EnforcerDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Enforcers" description="Policy enforcers binding models to adapters." />
      <DataTable
        columns={columns}
        rows={enforcers ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No enforcers found"
      />
    </div>
  )
}

function EnforcerDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: enforcer } = useEnforcer(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (e: Enforcer) => api.updateEnforcer(e.owner, e.name, e),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['enforcers'] }),
  })
  const [draft, setDraft] = useState<Partial<Enforcer>>({})

  if (!enforcer) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...enforcer, ...draft }
  const set = <K extends keyof Enforcer>(key: K, val: Enforcer[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...enforcer, ...draft })}
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
      </div>
    </DetailPanel>
  )
}
