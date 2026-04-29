import { useState } from 'react'
import { useAccount, useProviders, useProvider } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Provider } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const categoryColor: Record<string, 'blue' | 'green' | 'yellow' | 'red' | 'gray'> = {
  'OAuth': 'blue',
  'SAML': 'green',
  'SMS': 'yellow',
  'Email': 'red',
  'Storage': 'gray',
}

const columns: Column<Provider>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'category', title: 'Category', render: r => <Badge color={categoryColor[r.category] ?? 'gray'}>{r.category}</Badge> },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  { key: 'owner', title: 'Org' },
  { key: 'clientId', title: 'Client ID', mono: true, render: r => r.clientId ? `${r.clientId.slice(0, 16)}...` : '' },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Providers() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: providers } = useProviders(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <ProviderDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Providers" description="OAuth, SAML, SMS, email, and storage providers." />
      <DataTable
        columns={columns}
        rows={providers ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No providers found"
      />
    </div>
  )
}

function ProviderDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: provider } = useProvider(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (p: Provider) => api.updateProvider(p.owner, p.name, p),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['providers'] }),
  })
  const [draft, setDraft] = useState<Partial<Provider>>({})

  if (!provider) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...provider, ...draft }
  const set = <K extends keyof Provider>(key: K, val: Provider[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...provider, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Category"><TextInput value={merged.category} readOnly /></Field>
        <Field label="Type"><TextInput value={merged.type} readOnly /></Field>
        <Field label="Client ID">
          <TextInput value={merged.clientId} onChange={e => set('clientId', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Client Secret">
          <TextInput
            type="password"
            value={merged.clientSecret}
            onChange={e => set('clientSecret', e.target.value)}
            style={{ fontFamily: 'monospace' }}
          />
        </Field>
        <Field label="Host">
          <TextInput value={merged.host} onChange={e => set('host', e.target.value)} />
        </Field>
        <Field label="Port">
          <TextInput type="number" value={merged.port} onChange={e => set('port', Number(e.target.value))} />
        </Field>
        <Field label="Domain">
          <TextInput value={merged.domain} onChange={e => set('domain', e.target.value)} />
        </Field>
      </div>
    </DetailPanel>
  )
}
