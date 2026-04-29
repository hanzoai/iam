import { useState } from 'react'
import { useAccount, useTickets, useTicket } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Ticket } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const stateColor: Record<string, 'green' | 'yellow' | 'red' | 'gray'> = {
  Open: 'green',
  Pending: 'yellow',
  Closed: 'gray',
}

const columns: Column<Ticket>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  { key: 'title', title: 'Title' },
  {
    key: 'state', title: 'State',
    render: r => <Badge color={stateColor[r.state] ?? 'gray'}>{r.state || 'Unknown'}</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Tickets() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: tickets } = useTickets(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <TicketDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Tickets" description="Support and request tickets." />
      <DataTable
        columns={columns}
        rows={tickets ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No tickets found"
      />
    </div>
  )
}

function TicketDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: ticket } = useTicket(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (t: Ticket) => api.updateTicket(t.owner, t.name, t),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tickets'] }),
  })
  const [draft, setDraft] = useState<Partial<Ticket>>({})

  if (!ticket) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...ticket, ...draft }
  const set = <K extends keyof Ticket>(key: K, val: Ticket[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...ticket, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Type">
          <TextInput value={merged.type} onChange={e => set('type', e.target.value)} />
        </Field>
        <Field label="Title">
          <TextInput value={merged.title} onChange={e => set('title', e.target.value)} />
        </Field>
        <Field label="State">
          <TextInput value={merged.state} onChange={e => set('state', e.target.value)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Body">
          <TextArea
            value={merged.body}
            onChange={e => set('body', e.target.value)}
            style={{ minHeight: 160 }}
          />
        </Field>
      </div>
    </DetailPanel>
  )
}
