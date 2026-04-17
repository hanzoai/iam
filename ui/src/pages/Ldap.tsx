import { useState } from 'react'
import { useAccount, useLdaps, useLdap } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import type { Column } from '../components/DataTable'
import type { Ldap } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Ldap>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'owner', title: 'Org' },
  { key: 'serverName', title: 'Server Name' },
  { key: 'host', title: 'Host', mono: true },
  { key: 'port', title: 'Port', render: r => <span style={{ fontFamily: 'monospace' }}>{r.port}</span> },
  { key: 'admin', title: 'Admin' },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function LdapPage() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: ldaps } = useLdaps(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <LdapDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="LDAP" description="LDAP server connections for directory sync." />
      <DataTable
        columns={columns}
        rows={ldaps ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No LDAP configurations found"
      />
    </div>
  )
}

function LdapDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: ldap } = useLdap(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (l: Ldap) => api.updateLdap(l.owner, l.name, l),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ldaps'] }),
  })
  const [draft, setDraft] = useState<Partial<Ldap>>({})

  if (!ldap) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...ldap, ...draft }
  const set = <K extends keyof Ldap>(key: K, val: Ldap[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...ldap, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Server Name">
          <TextInput value={merged.serverName} onChange={e => set('serverName', e.target.value)} />
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
          <TextInput type="password" value={merged.passwd} onChange={e => set('passwd', e.target.value)} />
        </Field>
        <Field label="Base DN">
          <TextInput value={merged.baseDn} onChange={e => set('baseDn', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Auto Sync (minutes)">
          <TextInput type="number" value={merged.autoSync} onChange={e => set('autoSync', Number(e.target.value))} />
        </Field>
      </div>
    </DetailPanel>
  )
}
