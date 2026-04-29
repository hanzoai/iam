import { useState } from 'react'
import { useAccount, useKeys, useKey } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea, Toggle } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Key } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

function mask(s: string): string {
  if (!s || s.length < 12) return s ?? ''
  return s.slice(0, 8) + '...' + s.slice(-4)
}

const columns: Column<Key>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  { key: 'algorithm', title: 'Algorithm', mono: true },
  { key: 'key', title: 'Key', mono: true, render: r => mask(r.key) },
  {
    key: 'isEnabled', title: 'Enabled',
    render: r => r.isEnabled ? <Badge color="green">Yes</Badge> : <Badge color="red">No</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Keys() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: keys } = useKeys(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <KeyDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Keys" description="Cryptographic keys for signing and encryption." />
      <DataTable
        columns={columns}
        rows={keys ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No keys found"
      />
    </div>
  )
}

function KeyDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: key } = useKey(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (k: Key) => api.updateKey(k.owner, k.name, k),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['keys'] }),
  })
  const [draft, setDraft] = useState<Partial<Key>>({})

  if (!key) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...key, ...draft }
  const set = <K extends keyof Key>(k: K, val: Key[K]) => setDraft(d => ({ ...d, [k]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...key, ...draft })}
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
        <Field label="Algorithm">
          <TextInput value={merged.algorithm} readOnly style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Enabled">
          <Toggle checked={merged.isEnabled} onChange={v => set('isEnabled', v)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Key">
          <TextArea value={merged.key} onChange={e => set('key', e.target.value)} style={{ minHeight: 100 }} />
        </Field>
        <Field label="Certificate">
          <TextArea value={merged.certificate} onChange={e => set('certificate', e.target.value)} style={{ minHeight: 100 }} />
        </Field>
      </div>
    </DetailPanel>
  )
}
