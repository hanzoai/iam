import { useState } from 'react'
import { useAccount, useServers, useServer } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import type { Column } from '../components/DataTable'
import type { Server } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Server>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'protocol', title: 'Protocol', mono: true },
  { key: 'host', title: 'Host', mono: true },
  { key: 'port', title: 'Port', render: r => <span style={{ fontFamily: 'monospace' }}>{r.port}</span> },
  { key: 'admin', title: 'Admin' },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Servers() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: servers } = useServers(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <ServerDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Servers" description="Mail and notification servers." />
      <DataTable
        columns={columns}
        rows={servers ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No servers found"
      />
    </div>
  )
}

function ServerDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: server } = useServer(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (s: Server) => api.updateServer(s.owner, s.name, s),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['servers'] }),
  })
  const [draft, setDraft] = useState<Partial<Server>>({})

  if (!server) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...server, ...draft }
  const set = <K extends keyof Server>(key: K, val: Server[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...server, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Protocol">
          <TextInput value={merged.protocol} onChange={e => set('protocol', e.target.value)} />
        </Field>
        <Field label="Host">
          <TextInput value={merged.host} onChange={e => set('host', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Port">
          <TextInput type="number" value={merged.port} onChange={e => set('port', Number(e.target.value))} />
        </Field>
        <Field label="Admin">
          <TextInput value={merged.admin} onChange={e => set('admin', e.target.value)} />
        </Field>
        <Field label="Password">
          <TextInput type="password" value={merged.password} onChange={e => set('password', e.target.value)} />
        </Field>
      </div>
    </DetailPanel>
  )
}
