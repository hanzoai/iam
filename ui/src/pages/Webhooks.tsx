import { useState } from 'react'
import { useAccount, useWebhooks, useWebhook } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea, Toggle } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Webhook } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Webhook>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'organization', title: 'Org' },
  { key: 'url', title: 'URL', mono: true, render: r => r.url?.length > 40 ? r.url.slice(0, 40) + '...' : r.url },
  {
    key: 'events', title: 'Events',
    render: r => <span style={{ color: '#a3a3a3', fontSize: 11 }}>{(r.events ?? []).length} events</span>,
  },
  {
    key: 'isEnabled', title: 'Enabled',
    render: r => r.isEnabled ? <Badge color="green">Yes</Badge> : <Badge color="red">No</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Webhooks() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: webhooks } = useWebhooks(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <WebhookDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Webhooks" description="HTTP webhooks triggered on IAM events." />
      <DataTable
        columns={columns}
        rows={webhooks ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No webhooks found"
      />
    </div>
  )
}

function WebhookDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: wh } = useWebhook(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (w: Webhook) => api.updateWebhook(w.owner, w.name, w),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
  const [draft, setDraft] = useState<Partial<Webhook>>({})

  if (!wh) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...wh, ...draft }
  const set = <K extends keyof Webhook>(key: K, val: Webhook[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...wh, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Organization">
          <TextInput value={merged.organization} onChange={e => set('organization', e.target.value)} />
        </Field>
        <Field label="URL">
          <TextInput value={merged.url} onChange={e => set('url', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Content Type">
          <TextInput value={merged.contentType} onChange={e => set('contentType', e.target.value)} />
        </Field>
        <Field label="Enabled">
          <Toggle checked={merged.isEnabled} onChange={v => set('isEnabled', v)} />
        </Field>
        <Field label="User Extended">
          <Toggle checked={merged.isUserExtended} onChange={v => set('isUserExtended', v)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Events (one per line)">
          <TextArea
            value={(merged.events ?? []).join('\n')}
            onChange={e => set('events', e.target.value.split('\n').filter(Boolean))}
          />
        </Field>
      </div>
    </DetailPanel>
  )
}
