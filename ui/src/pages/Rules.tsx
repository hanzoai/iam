import { useState } from 'react'
import { useAccount, useRules, useRule } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import type { Column } from '../components/DataTable'
import type { Rule } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Rule>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'modelName', title: 'Model' },
  { key: 'adapterName', title: 'Adapter' },
  { key: 'ptype', title: 'PType', mono: true },
  { key: 'v0', title: 'V0', mono: true },
  { key: 'v1', title: 'V1', mono: true },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Rules() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: rules } = useRules(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <RuleDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Rules" description="Access control policy rules." />
      <DataTable
        columns={columns}
        rows={rules ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No rules found"
      />
    </div>
  )
}

function RuleDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: rule } = useRule(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (r: Rule) => api.updateRule(r.owner, r.name, r),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
  const [draft, setDraft] = useState<Partial<Rule>>({})

  if (!rule) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...rule, ...draft }
  const set = <K extends keyof Rule>(key: K, val: Rule[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...rule, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Model">
          <TextInput value={merged.modelName} onChange={e => set('modelName', e.target.value)} />
        </Field>
        <Field label="Adapter">
          <TextInput value={merged.adapterName} onChange={e => set('adapterName', e.target.value)} />
        </Field>
        <Field label="PType">
          <TextInput value={merged.ptype} onChange={e => set('ptype', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="V0">
          <TextInput value={merged.v0} onChange={e => set('v0', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="V1">
          <TextInput value={merged.v1} onChange={e => set('v1', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="V2">
          <TextInput value={merged.v2} onChange={e => set('v2', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="V3">
          <TextInput value={merged.v3} onChange={e => set('v3', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="V4">
          <TextInput value={merged.v4} onChange={e => set('v4', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="V5">
          <TextInput value={merged.v5} onChange={e => set('v5', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
      </div>
    </DetailPanel>
  )
}
