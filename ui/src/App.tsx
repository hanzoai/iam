import { Router, Route, Switch, Link, useLocation } from 'wouter'
import { useHashLocation } from 'wouter/use-hash-location'
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
import { Stub } from './pages/Stub'

interface NavItem {
  href: string
  label: string
  section?: string
}

const navItems: NavItem[] = [
  // Core (10 real pages)
  { href: '/', label: 'Users', section: 'Identity' },
  { href: '/organizations', label: 'Organizations' },
  { href: '/applications', label: 'Applications', section: 'OAuth' },
  { href: '/providers', label: 'Providers' },
  { href: '/roles', label: 'Roles', section: 'Access Control' },
  { href: '/permissions', label: 'Permissions' },
  { href: '/tokens', label: 'Tokens', section: 'Runtime' },
  { href: '/sessions', label: 'Sessions' },
  { href: '/certs', label: 'Certs', section: 'Security' },
  { href: '/webhooks', label: 'Webhooks' },
  // Stubs
  { href: '/groups', label: 'Groups', section: 'Stubs' },
  { href: '/ldap', label: 'LDAP' },
  { href: '/syncers', label: 'Syncers' },
  { href: '/enforcers', label: 'Enforcers' },
  { href: '/adapters', label: 'Adapters' },
  { href: '/models', label: 'Models' },
  { href: '/forms', label: 'Forms' },
  { href: '/tickets', label: 'Tickets' },
  { href: '/sites', label: 'Sites' },
  { href: '/invitations', label: 'Invitations' },
  { href: '/keys', label: 'Keys' },
  { href: '/servers', label: 'Servers' },
  { href: '/captcha', label: 'Captcha' },
  { href: '/verifications', label: 'Verifications' },
  { href: '/resources', label: 'Resources' },
  { href: '/records', label: 'Records' },
  { href: '/rules', label: 'Rules' },
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

// Stub routes
const stubRoutes = [
  'groups', 'ldap', 'syncers', 'enforcers', 'adapters', 'models', 'forms',
  'tickets', 'sites', 'invitations', 'keys', 'servers', 'captcha',
  'verifications', 'resources', 'records', 'rules',
] as const

export function App() {
  return (
    <Router hook={useHashLocation}>
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
          <div style={{ fontWeight: 600, fontSize: 15, padding: '4px 12px 12px', color: '#fff' }}>
            IAM Admin
          </div>
          <nav style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {navItems.map(n => (
              <div key={n.href}>
                {n.section && <div style={sectionStyle}>{n.section}</div>}
                <NavLink href={n.href} label={n.label} />
              </div>
            ))}
          </nav>
        </aside>
        <main style={{ flex: 1, overflow: 'auto', padding: 24 }}>
          <Switch>
            <Route path="/" component={Users} />
            <Route path="/organizations" component={Organizations} />
            <Route path="/applications" component={Applications} />
            <Route path="/providers" component={Providers} />
            <Route path="/roles" component={Roles} />
            <Route path="/permissions" component={Permissions} />
            <Route path="/tokens" component={Tokens} />
            <Route path="/sessions" component={Sessions} />
            <Route path="/certs" component={Certs} />
            <Route path="/webhooks" component={Webhooks} />
            {stubRoutes.map(r => (
              <Route key={r} path={`/${r}`}>
                <Stub title={r.charAt(0).toUpperCase() + r.slice(1)} />
              </Route>
            ))}
            <Route>
              <div style={{ color: '#737373' }}>Not found</div>
            </Route>
          </Switch>
        </main>
      </div>
    </Router>
  )
}
