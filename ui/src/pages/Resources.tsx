import { useState } from 'react'
import { useAccount, useResources, useResource } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Resource } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Resource>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'provider', title: 'Provider' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  { key: 'user', title: 'User' },
  { key: 'application', title: 'Application' },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Resources() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: resources } = useResources(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <ResourceDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Resources" description="Uploaded files and managed resources." />
      <DataTable
        columns={columns}
        rows={resources ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No resources found"
      />
    </div>
  )
}

function ResourceDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: resource } = useResource(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (r: Resource) => api.updateResource(r.owner, r.name, r),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['resources'] }),
  })
  const [draft, setDraft] = useState<Partial<Resource>>({})

  if (!resource) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...resource, ...draft }
  const set = <K extends keyof Resource>(key: K, val: Resource[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...resource, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Provider">
          <TextInput value={merged.provider} onChange={e => set('provider', e.target.value)} />
        </Field>
        <Field label="Type">
          <TextInput value={merged.type} onChange={e => set('type', e.target.value)} />
        </Field>
        <Field label="User">
          <TextInput value={merged.user} readOnly />
        </Field>
        <Field label="Application">
          <TextInput value={merged.application} readOnly />
        </Field>
        <Field label="URL">
          <TextInput value={merged.url} readOnly style={{ fontFamily: 'monospace' }} />
        </Field>
      </div>
    </DetailPanel>
  )
}
