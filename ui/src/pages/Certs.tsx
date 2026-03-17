import { useState } from 'react'
import { useAccount, useCerts, useCert } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput, TextArea } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Cert } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Cert>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'owner', title: 'Org' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  { key: 'scope', title: 'Scope' },
  { key: 'cryptoAlgorithm', title: 'Algorithm', mono: true },
  {
    key: 'expireInYears', title: 'Expire',
    render: r => <span>{r.expireInYears}y</span>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Certs() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: certs } = useCerts(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <CertDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Certs" description="X.509 and JWT signing certificates for applications." />
      <DataTable
        columns={columns}
        rows={certs ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No certificates found"
      />
    </div>
  )
}

function CertDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: cert } = useCert(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (c: Cert) => api.updateCert(c.owner, c.name, c),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['certs'] }),
  })
  const [draft, setDraft] = useState<Partial<Cert>>({})

  if (!cert) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...cert, ...draft }
  const set = <K extends keyof Cert>(key: K, val: Cert[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...cert, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Type"><TextInput value={merged.type} readOnly /></Field>
        <Field label="Scope">
          <TextInput value={merged.scope} onChange={e => set('scope', e.target.value)} />
        </Field>
        <Field label="Crypto Algorithm"><TextInput value={merged.cryptoAlgorithm} readOnly /></Field>
        <Field label="Expire In Years">
          <TextInput type="number" value={merged.expireInYears} onChange={e => set('expireInYears', Number(e.target.value))} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <Field label="Certificate (PEM)">
          <TextArea value={merged.certificate} onChange={e => set('certificate', e.target.value)} style={{ minHeight: 120 }} />
        </Field>
        <Field label="Private Key (PEM)">
          <TextArea value={merged.privateKey} onChange={e => set('privateKey', e.target.value)} style={{ minHeight: 120 }} />
        </Field>
      </div>
    </DetailPanel>
  )
}
