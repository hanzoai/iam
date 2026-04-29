import { useState } from 'react'
import { useAccount, useCaptchaProviders } from '../hooks/use-iam'
import { PageHeader } from '../components/PageHeader'
import { DetailPanel } from '../components/DetailPanel'
import { Field, TextInput } from '../components/Field'
import { Badge } from '../components/Badge'
import type { CaptchaProvider } from '../lib/api'
import { api } from '../lib/api'
import { useMutation, useQueryClient } from '@tanstack/react-query'

export function Captcha() {
  const { data: account } = useAccount()
  const owner = account?.owner ?? 'admin'
  const { data: providers } = useCaptchaProviders(owner)
  const [editing, setEditing] = useState<string | null>(null)

  const items = providers ?? []
  const selected = editing ? items.find(p => p.name === editing) : null

  if (selected) {
    return <CaptchaDetail provider={selected} onBack={() => setEditing(null)} />
  }

  return (
    <div>
      <PageHeader title="Captcha" description="CAPTCHA provider configuration for bot protection." />
      {items.length === 0 ? (
        <div style={{
          padding: 24, background: '#0a0a0a', border: '1px solid #262626',
          borderRadius: 8, color: '#525252', fontSize: 13,
        }}>
          No CAPTCHA providers configured
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {items.map(p => (
            <div
              key={p.name}
              onClick={() => setEditing(p.name)}
              style={{
                padding: '12px 16px', background: '#0a0a0a', border: '1px solid #262626',
                borderRadius: 8, cursor: 'pointer', display: 'flex',
                justifyContent: 'space-between', alignItems: 'center',
              }}
            >
              <div>
                <div style={{ fontWeight: 500, fontSize: 14, color: '#fff' }}>{p.name}</div>
                <div style={{ fontSize: 12, color: '#737373', marginTop: 2 }}>{p.owner}</div>
              </div>
              <Badge color="blue">{p.type || 'Default'}</Badge>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function CaptchaDetail({ provider, onBack }: { provider: CaptchaProvider; onBack: () => void }) {
  const qc = useQueryClient()
  const mutation = useMutation({
    mutationFn: (c: CaptchaProvider) => api.updateCaptchaProvider(c.owner, c.name, c),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['captcha-providers'] }),
  })
  const [draft, setDraft] = useState<Partial<CaptchaProvider>>({})

  const merged = { ...provider, ...draft }
  const set = <K extends keyof CaptchaProvider>(key: K, val: CaptchaProvider[K]) => setDraft(d => ({ ...d, [key]: val }))

  return (
    <DetailPanel
      name={`${provider.owner}/${provider.name}`}
      onBack={onBack}
      onSave={() => mutation.mutate({ ...provider, ...draft })}
      saving={mutation.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Field label="Name"><TextInput value={merged.name} readOnly /></Field>
        <Field label="Type">
          <TextInput value={merged.type} onChange={e => set('type', e.target.value)} />
        </Field>
        <Field label="Site Key">
          <TextInput value={merged.siteKey} onChange={e => set('siteKey', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
        <Field label="Secret Key">
          <TextInput type="password" value={merged.secretKey} onChange={e => set('secretKey', e.target.value)} style={{ fontFamily: 'monospace' }} />
        </Field>
      </div>
    </DetailPanel>
  )
}
