import { useState, useEffect } from 'react'
import { Router, Route, Switch, Link, useLocation } from 'wouter'
import { useHashLocation } from 'wouter/use-hash-location'
import { CommandPalette } from './components/CommandPalette'
import { Users } from './pages/Users'
import { Organizations } from './pages/Organizations'
import { Applications } from './pages/Applications'
import { Providers } from './pages/Providers'
import { Roles } from './pages/Roles'
import { Permissions } from './pages/Permissions'
import { Tokens } from './pages/Tokens'
import { Sessions } from './pages/Sessions'
import { Certs } from './pages/Certs'
import { Webhooks } from './pages/Webhooks'
import { Groups } from './pages/Groups'
import { LdapPage } from './pages/Ldap'
import { Syncers } from './pages/Syncers'
import { Enforcers } from './pages/Enforcers'
import { Adapters } from './pages/Adapters'
import { Models } from './pages/Models'
import { Forms } from './pages/Forms'
import { Tickets } from './pages/Tickets'
import { Sites } from './pages/Sites'
import { Invitations } from './pages/Invitations'
import { Keys } from './pages/Keys'
import { Servers } from './pages/Servers'
import { Captcha } from './pages/Captcha'
import { Verifications } from './pages/Verifications'
import { Resources } from './pages/Resources'
import { Records } from './pages/Records'
import { Rules } from './pages/Rules'

interface NavItem {
  href: string
  label: string
}

interface NavSection {
  title: string
  items: NavItem[]
}

const sections: NavSection[] = [
  {
    title: 'Identity',
    items: [
      { href: '/', label: 'Users' },
      { href: '/groups', label: 'Groups' },
      { href: '/organizations', label: 'Organizations' },
    ],
  },
  {
    title: 'Applications',
    items: [
      { href: '/applications', label: 'Applications' },
      { href: '/providers', label: 'Providers' },
      { href: '/forms', label: 'Forms' },
    ],
  },
  {
    title: 'Access Control',
    items: [
      { href: '/roles', label: 'Roles' },
      { href: '/permissions', label: 'Permissions' },
      { href: '/enforcers', label: 'Enforcers' },
      { href: '/models', label: 'Models' },
      { href: '/adapters', label: 'Adapters' },
      { href: '/rules', label: 'Rules' },
    ],
  },
  {
    title: 'Authentication',
    items: [
      { href: '/tokens', label: 'Tokens' },
      { href: '/sessions', label: 'Sessions' },
      { href: '/certs', label: 'Certs' },
      { href: '/keys', label: 'Keys' },
      { href: '/captcha', label: 'Captcha' },
    ],
  },
  {
    title: 'Infrastructure',
    items: [
      { href: '/servers', label: 'Servers' },
      { href: '/ldap', label: 'LDAP' },
      { href: '/syncers', label: 'Syncers' },
      { href: '/sites', label: 'Sites' },
    ],
  },
  {
    title: 'Activity',
    items: [
      { href: '/records', label: 'Records' },
      { href: '/verifications', label: 'Verifications' },
      { href: '/tickets', label: 'Tickets' },
      { href: '/invitations', label: 'Invitations' },
      { href: '/webhooks', label: 'Webhooks' },
      { href: '/resources', label: 'Resources' },
    ],
  },
]

const sectionStyle: React.CSSProperties = {
  fontSize: 10,
  fontWeight: 600,
  color: '#525252',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  padding: '10px 12px 4px',
}

function NavLink({ href, label }: { href: string; label: string }) {
  const [location] = useLocation()
  const active = href === '/' ? location === '/' : location.startsWith(href)
  return (
    <Link
      href={href}
      style={{
        display: 'block',
        padding: '5px 12px',
        borderRadius: 6,
        color: active ? '#fff' : '#a3a3a3',
        background: active ? '#262626' : 'transparent',
        textDecoration: 'none',
        fontSize: 13,
      }}
    >
      {label}
    </Link>
  )
}

export function App() {
  const [cmdK, setCmdK] = useState(false)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setCmdK(v => !v)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  return (
    <Router hook={useHashLocation}>
      <CommandPalette open={cmdK} onClose={() => setCmdK(false)} />
      <div style={{ display: 'flex', height: '100vh', background: '#000', color: '#e5e5e5' }}>
        <aside
          style={{
            width: 200,
            borderRight: '1px solid #262626',
            padding: '12px 8px',
            display: 'flex',
            flexDirection: 'column',
            gap: 1,
            flexShrink: 0,
            overflowY: 'auto',
          }}
        >
          <div style={{ fontWeight: 600, fontSize: 15, padding: '4px 12px 8px', color: '#fff' }}>
            IAM Admin
          </div>
          <button
            onClick={() => setCmdK(true)}
            style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '6px 12px', margin: '0 0 8px', borderRadius: 6,
              border: '1px solid #262626', background: '#0a0a0a',
              color: '#525252', fontSize: 12, cursor: 'pointer',
            }}
          >
            <span>Search...</span>
            <kbd style={{ fontSize: 10, background: '#1a1a1a', padding: '1px 5px', borderRadius: 3, border: '1px solid #333' }}>
              {navigator.platform.includes('Mac') ? '\u2318' : 'Ctrl'}K
            </kbd>
          </button>
          <nav style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {sections.map(s => (
              <div key={s.title}>
                <div style={sectionStyle}>{s.title}</div>
                {s.items.map(n => <NavLink key={n.href} href={n.href} label={n.label} />)}
              </div>
            ))}
          </nav>
        </aside>
        <main style={{ flex: 1, overflow: 'auto', padding: 24 }}>
          <Switch>
            <Route path="/" component={Users} />
            <Route path="/groups" component={Groups} />
            <Route path="/organizations" component={Organizations} />
            <Route path="/applications" component={Applications} />
            <Route path="/providers" component={Providers} />
            <Route path="/forms" component={Forms} />
            <Route path="/roles" component={Roles} />
            <Route path="/permissions" component={Permissions} />
            <Route path="/enforcers" component={Enforcers} />
            <Route path="/models" component={Models} />
            <Route path="/adapters" component={Adapters} />
            <Route path="/rules" component={Rules} />
            <Route path="/tokens" component={Tokens} />
            <Route path="/sessions" component={Sessions} />
            <Route path="/certs" component={Certs} />
            <Route path="/keys" component={Keys} />
            <Route path="/captcha" component={Captcha} />
            <Route path="/servers" component={Servers} />
            <Route path="/ldap" component={LdapPage} />
            <Route path="/syncers" component={Syncers} />
            <Route path="/sites" component={Sites} />
            <Route path="/records" component={Records} />
            <Route path="/verifications" component={Verifications} />
            <Route path="/tickets" component={Tickets} />
            <Route path="/invitations" component={Invitations} />
            <Route path="/webhooks" component={Webhooks} />
            <Route path="/resources" component={Resources} />
            <Route>
              <div style={{ color: '#737373' }}>Not found</div>
            </Route>
          </Switch>
        </main>
      </div>
    </Router>
  )
}
