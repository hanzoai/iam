import { useState } from 'react'
import { useAccount, useSites, useSite } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, Toggle } from '../components/Field'
import type { Column } from '../components/DataTable'
import type { Site } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Site>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'owner', title: 'Org' },
  { key: 'domain', title: 'Domain', mono: true },
  { key: 'host', title: 'Host', mono: true },
  { key: 'port', title: 'Port', render: r => <span style={{ fontFamily: 'monospace' }}>{r.port}</span> },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Sites() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: sites } = useSites(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <SiteDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Sites" description="Registered web sites and domains." />
      <DataTable
        columns={columns}
        rows={sites ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No sites found"
      />
    </div>
  )
}

function SiteDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: site } = useSite(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (s: Site) => api.updateSite(s.owner, s.name, s),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sites'] }),
  })
  const [draft, setDraft] = useState<Partial<Site>>({})

  if (!site) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...site, ...draft }
  const set = <K extends keyof Site>(key: K, val: Site[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...site, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Domain">
          <TextInput value={merged.domain} onChange={e => set('domain', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Host">
          <TextInput value={merged.host} onChange={e => set('host', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Port">
          <TextInput type="number" value={merged.port} onChange={e => set('port', Number(e.target.value))} />
        </Field>
        <Field label="HTTPS">
          <Toggle checked={merged.enableHttps} onChange={v => set('enableHttps', v)} />
        </Field>
      </div>
    </DetailPanel>
  )
}
