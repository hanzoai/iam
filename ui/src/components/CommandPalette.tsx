import { useState, useEffect, useRef, useCallback } from 'react'
import { useLocation } from 'wouter'
import { api } from '../lib/api'
import type { User, Organization, Application } from '../lib/api'

interface Result {
  id: string
  label: string
  section: string
  action: () => void
}

const pages: { label: string; path: string; section: string }[] = [
  { label: 'Users', path: '/', section: 'Identity' },
  { label: 'Groups', path: '/groups', section: 'Identity' },
  { label: 'Organizations', path: '/organizations', section: 'Identity' },
  { label: 'Applications', path: '/applications', section: 'Applications' },
  { label: 'Providers', path: '/providers', section: 'Applications' },
  { label: 'Forms', path: '/forms', section: 'Applications' },
  { label: 'Roles', path: '/roles', section: 'Access Control' },
  { label: 'Permissions', path: '/permissions', section: 'Access Control' },
  { label: 'Enforcers', path: '/enforcers', section: 'Access Control' },
  { label: 'Models', path: '/models', section: 'Access Control' },
  { label: 'Adapters', path: '/adapters', section: 'Access Control' },
  { label: 'Rules', path: '/rules', section: 'Access Control' },
  { label: 'Tokens', path: '/tokens', section: 'Authentication' },
  { label: 'Sessions', path: '/sessions', section: 'Authentication' },
  { label: 'Certs', path: '/certs', section: 'Authentication' },
  { label: 'Keys', path: '/keys', section: 'Authentication' },
  { label: 'Captcha', path: '/captcha', section: 'Authentication' },
  { label: 'Servers', path: '/servers', section: 'Infrastructure' },
  { label: 'LDAP', path: '/ldap', section: 'Infrastructure' },
  { label: 'Syncers', path: '/syncers', section: 'Infrastructure' },
  { label: 'Sites', path: '/sites', section: 'Infrastructure' },
  { label: 'Records', path: '/records', section: 'Activity' },
  { label: 'Verifications', path: '/verifications', section: 'Activity' },
  { label: 'Tickets', path: '/tickets', section: 'Activity' },
  { label: 'Invitations', path: '/invitations', section: 'Activity' },
  { label: 'Webhooks', path: '/webhooks', section: 'Activity' },
  { label: 'Resources', path: '/resources', section: 'Activity' },
]

const quickActions: { label: string; path: string }[] = [
  { label: 'Create User', path: '/' },
  { label: 'Create Organization', path: '/organizations' },
  { label: 'Create Application', path: '/applications' },
  { label: 'View Tokens', path: '/tokens' },
  { label: 'Clear Sessions', path: '/sessions' },
]

function fuzzy(query: string, text: string): boolean {
  const q = query.toLowerCase()
  const t = text.toLowerCase()
  let qi = 0
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) qi++
  }
  return qi === q.length
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('')
  const [idx, setIdx] = useState(0)
  const [entities, setEntities] = useState<Result[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const [, navigate] = useLocation()
  const debounceRef = useRef<ReturnType<typeof setTimeout>>()

  useEffect(() => {
    if (open) {
      setQuery('')
      setIdx(0)
      setEntities([])
      setTimeout(() => inputRef.current?.focus(), 0)
    }
  }, [open])

  const searchEntities = useCallback((q: string) => {
    if (q.length < 2) { setEntities([]); return }
    const results: Result[] = []
    const done = { users: false, orgs: false, apps: false }
    const check = () => {
      if (done.users && done.orgs && done.apps) setEntities(results)
    }
    api.searchUsers(q).then(r => {
      (r.data ?? []).slice(0, 5).forEach((u: User) => {
        results.push({ id: `user:${u.owner}/${u.name}`, label: `${u.displayName || u.name} (${u.email || u.owner})`, section: 'Users', action: () => { navigate('/'); onClose() } })
      })
      done.users = true; check()
    }).catch(() => { done.users = true; check() })
    api.searchOrganizations(q).then(r => {
      (r.data ?? []).slice(0, 5).forEach((o: Organization) => {
        results.push({ id: `org:${o.owner}/${o.name}`, label: o.displayName || o.name, section: 'Organizations', action: () => { navigate('/organizations'); onClose() } })
      })
      done.orgs = true; check()
    }).catch(() => { done.orgs = true; check() })
    api.searchApplications(q).then(r => {
      (r.data ?? []).slice(0, 5).forEach((a: Application) => {
        results.push({ id: `app:${a.owner}/${a.name}`, label: a.displayName || a.name, section: 'Applications', action: () => { navigate('/applications'); onClose() } })
      })
      done.apps = true; check()
    }).catch(() => { done.apps = true; check() })
  }, [navigate, onClose])

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => searchEntities(query), 200)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [query, searchEntities])

  const pageResults: Result[] = pages
    .filter(p => !query || fuzzy(query, p.label))
    .map(p => ({
      id: `page:${p.path}`,
      label: p.label,
      section: p.section,
      action: () => { navigate(p.path); onClose() },
    }))

  const actionResults: Result[] = query
    ? quickActions.filter(a => fuzzy(query, a.label)).map(a => ({
      id: `action:${a.label}`,
      label: a.label,
      section: 'Quick Actions',
      action: () => { navigate(a.path); onClose() },
    }))
    : []

  const all = [...actionResults, ...entities, ...pageResults]

  useEffect(() => { setIdx(0) }, [query])

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx(i => Math.min(i + 1, all.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx(i => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter' && all[idx]) { e.preventDefault(); all[idx].action() }
    else if (e.key === 'Escape') { e.preventDefault(); onClose() }
  }

  if (!open) return null

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
        display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
        paddingTop: 120, zIndex: 9999,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: 520, background: '#0a0a0a', border: '1px solid #262626',
          borderRadius: 10, overflow: 'hidden',
        }}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={onKey}
          placeholder="Search pages, entities, actions..."
          style={{
            width: '100%', background: 'transparent', border: 'none',
            borderBottom: '1px solid #262626', padding: '14px 16px',
            color: '#e5e5e5', fontSize: 14, outline: 'none',
          }}
        />
        <div style={{ maxHeight: 360, overflowY: 'auto' }}>
          {all.length === 0 && query && (
            <div style={{ padding: '16px', color: '#525252', fontSize: 13 }}>No results</div>
          )}
          {all.map((r, i) => (
            <div
              key={r.id}
              onClick={r.action}
              style={{
                padding: '8px 16px',
                background: i === idx ? '#1a1a1a' : 'transparent',
                cursor: 'pointer',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              }}
            >
              <span style={{ fontSize: 13, color: '#e5e5e5' }}>{r.label}</span>
              <span style={{ fontSize: 10, color: '#525252', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{r.section}</span>
            </div>
          ))}
        </div>
        <div style={{ borderTop: '1px solid #262626', padding: '8px 16px', display: 'flex', gap: 16 }}>
          <span style={{ fontSize: 11, color: '#525252' }}>
            <kbd style={{ background: '#262626', padding: '1px 4px', borderRadius: 3, fontSize: 10 }}>↑↓</kbd> navigate
          </span>
          <span style={{ fontSize: 11, color: '#525252' }}>
            <kbd style={{ background: '#262626', padding: '1px 4px', borderRadius: 3, fontSize: 10 }}>↵</kbd> select
          </span>
          <span style={{ fontSize: 11, color: '#525252' }}>
            <kbd style={{ background: '#262626', padding: '1px 4px', borderRadius: 3, fontSize: 10 }}>esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  )
}
