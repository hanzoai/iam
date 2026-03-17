import { useState } from 'react'
import { useAccount, useOrganizations, useOrganization, useUpdateOrganization } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, Toggle } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Organization } from '../lib/api'

const columns: Column<Organization>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'websiteUrl', title: 'Website', mono: true },
  {
    key: 'tags', title: 'Tags',
    render: r => (r.tags ?? []).map(t => <Badge key={t} color="blue">{t}</Badge>),
  },
  { key: 'passwordType', title: 'Password Type' },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Organizations() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: orgs } = useOrganizations(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <OrgDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Organizations" description="Manage organizations, branding, and password policies." />
      <DataTable
        columns={columns}
        rows={orgs ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No organizations found"
      />
    </div>
  )
}

function OrgDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: org } = useOrganization(owner, name)
  const mutation = useUpdateOrganization()
  const [draft, setDraft] = useState<Partial<Organization>>({})

  if (!org) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...org, ...draft }
  const set = <K extends keyof Organization>(key: K, val: Organization[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...org, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Website URL">
          <TextInput value={merged.websiteUrl} onChange={e => set('websiteUrl', e.target.value)} />
        </Field>
        <Field label="Favicon">
          <TextInput value={merged.favicon} onChange={e => set('favicon', e.target.value)} />
        </Field>
        <Field label="Password Type">
          <TextInput value={merged.passwordType} onChange={e => set('passwordType', e.target.value)} />
        </Field>
        <Field label="Default Avatar">
          <TextInput value={merged.defaultAvatar} onChange={e => set('defaultAvatar', e.target.value)} />
        </Field>
        <Field label="Profile Public">
          <Toggle checked={merged.isProfilePublic} onChange={v => set('isProfilePublic', v)} />
        </Field>
        <Field label="Soft Deletion">
          <Toggle checked={merged.enableSoftDeletion} onChange={v => set('enableSoftDeletion', v)} />
        </Field>
      </div>
    </DetailPanel>
  )
}
