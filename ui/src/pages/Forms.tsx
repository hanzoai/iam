import { useState } from 'react'
import { useAccount, useForms, useForm } from '../hooks/use-iam'
import { DataTable } from '../components/DataTable'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import { Badge } from '../components/Badge'
import type { Column } from '../components/DataTable'
import type { Form } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

const columns: Column<Form>[] = [
  { key: 'name', title: 'Name', render: r => <span style={{ fontWeight: 500 }}>{r.name}</span> },
  { key: 'displayName', title: 'Display Name' },
  { key: 'owner', title: 'Org' },
  { key: 'type', title: 'Type', render: r => <Badge color="blue">{r.type}</Badge> },
  {
    key: 'formItems', title: 'Fields',
    render: r => <span style={{ fontFamily: 'monospace' }}>{(r.formItems ?? []).length}</span>,
  },
  {
    key: 'createdTime', title: 'Created',
    render: r => <span style={{ color: '#737373' }}>{r.createdTime?.slice(0, 10)}</span>,
  },
]

export function Forms() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: forms } = useForms(owner)
  const [selected, setSelected] = useState<{ owner: string; name: string } | null>(null)

  if (selected) {
    return <FormDetail owner={selected.owner} name={selected.name} onBack={() => setSelected(null)} />
  }

  return (
    <div>
      <PageHeader title="Forms" description="Custom login and signup forms." />
      <DataTable
        columns={columns}
        rows={forms ?? []}
        rowKey={r => `${r.owner}/${r.name}`}
        onRowClick={r => setSelected({ owner: r.owner, name: r.name })}
        empty="No forms found"
      />
    </div>
  )
}

function FormDetail({ owner, name, onBack }: { owner: string; name: string; onBack: () => void }) {
  const { data: form } = useForm(owner, name)
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (f: Form) => api.updateForm(f.owner, f.name, f),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['forms'] }),
  })
  const [draft, setDraft] = useState<Partial<Form>>({})

  if (!form) return <div style={{ color: '#525252' }}>Loading...</div>

  const merged = { ...form, ...draft }
  const set = <K extends keyof Form>(key: K, val: Form[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${owner}/${name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...form, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Display Name">
          <TextInput value={merged.displayName} onChange={e => set('displayName', e.target.value)} />
        </Field>
        <Field label="Type">
          <TextInput value={merged.type} onChange={e => set('type', e.target.value)} />
        </Field>
      </div>
      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: 12, color: '#737373', marginBottom: 8 }}>Form Items</div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #262626' }}>
              <th style={{ textAlign: 'left', padding: '4px 8px', color: '#525252' }}>Name</th>
              <th style={{ textAlign: 'left', padding: '4px 8px', color: '#525252' }}>Visible</th>
              <th style={{ textAlign: 'left', padding: '4px 8px', color: '#525252' }}>Required</th>
              <th style={{ textAlign: 'left', padding: '4px 8px', color: '#525252' }}>Rule</th>
            </tr>
          </thead>
          <tbody>
            {(merged.formItems ?? []).map((item, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #171717' }}>
                <td style={{ padding: '4px 8px', color: '#e5e5e5' }}>{item.name}</td>
                <td style={{ padding: '4px 8px' }}>
                  <Badge color={item.visible ? 'green' : 'gray'}>{item.visible ? 'Yes' : 'No'}</Badge>
                </td>
                <td style={{ padding: '4px 8px' }}>
                  <Badge color={item.required ? 'yellow' : 'gray'}>{item.required ? 'Yes' : 'No'}</Badge>
                </td>
                <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#737373' }}>{item.rule}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DetailPanel>
  )
}
