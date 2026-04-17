import { useState } from 'react'
import { useAccount, useModels, useModel } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea } from '../components/Field'
import type { Column } from '../components/DataTable'
import type { Model } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Model>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'owner', title: 'Org' },
  {
    key: 'modelText', title: 'Model Text',
    render: r => (
      <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#a3a3a3' }}>
        {(r.modelText ?? '').slice(0, 60)}{(r.modelText ?? '').length > 60 ? '...' : ''}
      </span>
    ),
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Models() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: models } = useModels(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <ModelDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Models" description="Access control models defining policy structure." />
      <DataTable
        columns={columns}
        rows={models ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No models found"
      />
    </div>
  )
}

function ModelDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: model } = useModel(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (m: Model) => api.updateModel(m.owner, m.name, m),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['models'] }),
  })
  const [draft, setDraft] = useState<Partial<Model>>({})

  if (!model) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...model, ...draft }
  const set = <K extends keyof Model>(key: K, val: Model[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...model, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Model Text">
          <TextArea
            value={merged.modelText}
            onChange={e => set('modelText', e.target.value)}
            style={{ minHeight: 200 }}
          />
        </Field>
      </div>
    </DetailPanel>
  )
}
