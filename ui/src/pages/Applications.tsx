import { useState } from 'react'
import { useAccount, useApplications, useApplication, useUpdateApplication } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea, Toggle } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Application } from '../lib/api'

const columns: Column<Application>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'organization', title: 'Org' },
  {
    key: 'grantTypes', title: 'Grant Types',
    render: r => (r.grantTypes ?? []).slice(0, 2).map(g =>
      <Badge key={g} color="blue">{g}</Badge>
    ),
  },
  {
    key: 'redirectUris', title: 'Redirect URIs',
    render: r => <span style={{ color: '#a3a3a3', fontSize: 11 }}>{(r.redirectUris ?? []).length} URIs</span>,
  },
  {
    key: 'enablePassword', title: 'Password',
    render: r => r.enablePassword ? <Badge color="green">On</Badge> : <Badge>Off</Badge>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Applications() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: apps } = useApplications(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <AppDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Applications" description="OAuth/OIDC applications with client credentials and redirect URIs." />
      <DataTable
        columns={columns}
        rows={apps ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No applications found"
      />
    </div>
  )
}

function AppDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: app } = useApplication(owner, name)
  const mutation = useUpdateApplication()
  const [draft, setDraft] = useState<Partial<Application>>({})

  if (!app) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...app, ...draft }
  const set = <K extends keyof Application>(key: K, val: Application[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...app, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Client ID"><TextInput value={merged.clientId} readOnly style={{ fontFamily: 'monospace' }} /></Field>
        <Field label="Client Secret"><TextInput value={merged.clientSecret} readOnly style={{ fontFamily: 'monospace' }} /></Field>
        <Field label="Organization">
          <TextInput value={merged.organization} onChange={e => set('organization', e.target.value)} />
        </Field>
        <Field label="Token Format">
          <TextInput value={merged.tokenFormat} onChange={e => set('tokenFormat', e.target.value)} />
        </Field>
        <Field label="Expire In Hours">
          <TextInput type="number" value={merged.expireInHours} onChange={e => set('expireInHours', Number(e.target.value))} />
        </Field>
        <Field label="Refresh Expire In Hours">
          <TextInput type="number" value={merged.refreshExpireInHours} onChange={e => set('refreshExpireInHours', Number(e.target.value))} />
        </Field>
        <Field label="Enable Password">
          <Toggle checked={merged.enablePassword} onChange={v => set('enablePassword', v)} />
        </Field>
        <Field label="Enable Signup">
          <Toggle checked={merged.enableSignUp} onChange={v => set('enableSignUp', v)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Redirect URIs (one per line)">
          <TextArea
            value={(merged.redirectUris ?? []).join('\n')}
            onChange={e => set('redirectUris', e.target.value.split('\n').filter(Boolean))}
          />
        </Field>
        <Field label="Grant Types (comma-separated)">
          <TextInput
            value={(merged.grantTypes ?? []).join(', ')}
            onChange={e => set('grantTypes', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
          />
        </Field>
      </div>
    </DetailPanel>
  )
}
