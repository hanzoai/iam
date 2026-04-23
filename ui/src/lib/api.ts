// Typed API client for IAM backend — all calls use cookies (same origin).
// IAM API pattern:
//   GET  /api/get-{entity}s?owner={org}      → list (returns { data: T[], data2: T[] } with pagination)
//   GET  /api/get-{entity}?id={org}/{name}    → single
//   POST /api/add-{entity}                    → create
//   POST /api/update-{entity}?id={org}/{name} → update
//   POST /api/delete-{entity}                 → delete

export class APIError extends Error {
  constructor(public status: number, public body: unknown) {
    super(`API ${status}`)
    this.name = 'APIError'
  }
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method,
    credentials: 'include',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const data = await res.json()
  if (!res.ok) throw new APIError(res.status, data)
  return data as T
}

// IAM list responses wrap items in `data` (current page) and `data2` (all matching).
// Pagination: p=page&pageSize=N
export interface ListResponse<T> {
  data: T[]
  data2?: T[]
}

function listUrl(entity: string, owner: string, extra?: Record<string, string>): string {
  const params = new URLSearchParams({ owner })
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      if (v) params.set(k, v)
    }
  }
  return `/api/get-${entity}s?${params}`
}

function getUrl(entity: string, owner: string, name: string): string {
  return `/api/get-${entity}?id=${owner}/${encodeURIComponent(name)}`
}

function updateUrl(entity: string, owner: string, name: string): string {
  return `/api/update-${entity}?id=${owner}/${encodeURIComponent(name)}`
}

function deleteUrl(entity: string): string {
  return `/api/delete-${entity}`
}

// --- Types (matching Go backend JSON tags) ---

export interface User {
  owner: string
  name: string
  createdTime: string
  updatedTime: string
  id: string
  type: string
  displayName: string
  firstName: string
  lastName: string
  avatar: string
  email: string
  phone: string
  countryCode: string
  isAdmin: boolean
  isForbidden: boolean
  isDeleted: boolean
  signupApplication: string
  groups: string[]
}

export interface Organization {
  owner: string
  name: string
  createdTime: string
  displayName: string
  websiteUrl: string
  favicon: string
  passwordType: string
  tags: string[]
  masterPassword: string
  defaultAvatar: string
  enableSoftDeletion: boolean
  isProfilePublic: boolean
  accountItems: { name: string; visible: boolean; viewRule: string; modifyRule: string }[]
}

export interface Application {
  owner: string
  name: string
  createdTime: string
  displayName: string
  logo: string
  homepageUrl: string
  organization: string
  cert: string
  enablePassword: boolean
  enableSignUp: boolean
  enableCodeSignin: boolean
  clientId: string
  clientSecret: string
  redirectUris: string[]
  tokenFormat: string
  expireInHours: number
  refreshExpireInHours: number
  grantTypes: string[]
  providers: { name: string; canSignUp: boolean; canSignIn: boolean; canUnlink: boolean; prompted: boolean; signupGroup: string }[]
  signinMethods: { name: string; displayName: string; rule: string }[]
  signupItems: { name: string; visible: boolean; required: boolean; prompted: boolean; rule: string }[]
}

export interface Provider {
  owner: string
  name: string
  createdTime: string
  displayName: string
  category: string
  type: string
  clientId: string
  clientSecret: string
  host: string
  port: number
  metadata: string
  domain: string
}

export interface Role {
  owner: string
  name: string
  createdTime: string
  displayName: string
  description: string
  users: string[]
  roles: string[]
  domains: string[]
  isEnabled: boolean
}

export interface Permission {
  owner: string
  name: string
  createdTime: string
  displayName: string
  description: string
  model: string
  adapter: string
  resourceType: string
  resources: string[]
  actions: string[]
  effect: string
  isEnabled: boolean
  submitter: string
  approver: string
  approveTime: string
  state: string
}

export interface Token {
  owner: string
  name: string
  createdTime: string
  application: string
  organization: string
  user: string
  code: string
  accessToken: string
  refreshToken: string
  expiresIn: number
  scope: string
  tokenType: string
}

export interface Session {
  owner: string
  name: string
  createdTime: string
  sessionId: string[]
}

export interface Cert {
  owner: string
  name: string
  createdTime: string
  displayName: string
  scope: string
  type: string
  cryptoAlgorithm: string
  bitSize: number
  expireInYears: number
  certificate: string
  privateKey: string
}

export interface Webhook {
  owner: string
  name: string
  createdTime: string
  organization: string
  url: string
  contentType: string
  events: string[]
  isEnabled: boolean
  isUserExtended: boolean
  headers: { name: string; value: string }[]
}

export interface Group {
  owner: string
  name: string
  createdTime: string
  updatedTime: string
  displayName: string
  type: string
  users: string[]
}

export interface Ldap {
  owner: string
  name: string
  createdTime: string
  serverName: string
  host: string
  port: number
  admin: string
  passwd: string
  baseDn: string
  autoSync: number
}

export interface Syncer {
  owner: string
  name: string
  createdTime: string
  type: string
  table: string
  databaseType: string
  database: string
  host: string
  port: number
  user: string
  password: string
  isEnabled: boolean
}

export interface Enforcer {
  owner: string
  name: string
  createdTime: string
  displayName: string
  model: string
  adapter: string
}

export interface Adapter {
  owner: string
  name: string
  createdTime: string
  type: string
  databaseType: string
  host: string
  port: number
  user: string
  password: string
  database: string
  table: string
}

export interface Model {
  owner: string
  name: string
  createdTime: string
  displayName: string
  modelText: string
}

export interface Form {
  owner: string
  name: string
  createdTime: string
  type: string
  displayName: string
  formItems: { name: string; visible: boolean; required: boolean; prompted: boolean; rule: string }[]
}

export interface Ticket {
  owner: string
  name: string
  createdTime: string
  type: string
  title: string
  body: string
  state: string
}

export interface Site {
  owner: string
  name: string
  createdTime: string
  displayName: string
  domain: string
  host: string
  port: number
  enableHttps: boolean
}

export interface Invitation {
  owner: string
  name: string
  createdTime: string
  sender: string
  recipient: string
  state: string
  application: string
}

export interface Key {
  owner: string
  name: string
  createdTime: string
  displayName: string
  type: string
  algorithm: string
  key: string
  certificate: string
  isEnabled: boolean
}

export interface Server {
  owner: string
  name: string
  createdTime: string
  protocol: string
  host: string
  port: number
  admin: string
  password: string
}

export interface CaptchaProvider {
  owner: string
  name: string
  createdTime: string
  type: string
  siteKey: string
  secretKey: string
}

export interface Verification {
  owner: string
  name: string
  createdTime: string
  type: string
  provider: string
  receiver: string
  code: string
  isUsed: boolean
}

export interface Resource {
  owner: string
  name: string
  createdTime: string
  provider: string
  type: string
  user: string
  application: string
  url: string
}

export interface AuditRecord {
  owner: string
  name: string
  createdTime: string
  method: string
  requestUri: string
  action: string
  isTriggered: boolean
  organization: string
  user: string
  clientIp: string
}

export interface Rule {
  owner: string
  name: string
  createdTime: string
  modelName: string
  adapterName: string
  ptype: string
  v0: string
  v1: string
  v2: string
  v3: string
  v4: string
  v5: string
}

// --- API methods ---

export const api = {
  // Users
  getUsers: (owner: string) =>
    request<ListResponse<User>>('GET', listUrl('user', owner)),
  getUser: (owner: string, name: string) =>
    request<{ data: User }>('GET', getUrl('user', owner, name)),
  updateUser: (owner: string, name: string, user: User) =>
    request<{ data: string }>('POST', updateUrl('user', owner, name), user),
  deleteUser: (user: User) =>
    request<{ data: string }>('POST', deleteUrl('user'), user),

  // Organizations
  getOrganizations: (owner: string) =>
    request<ListResponse<Organization>>('GET', listUrl('organization', owner)),
  getOrganization: (owner: string, name: string) =>
    request<{ data: Organization }>('GET', getUrl('organization', owner, name)),
  updateOrganization: (owner: string, name: string, org: Organization) =>
    request<{ data: string }>('POST', updateUrl('organization', owner, name), org),

  // Applications
  getApplications: (owner: string) =>
    request<ListResponse<Application>>('GET', listUrl('application', owner)),
  getApplication: (owner: string, name: string) =>
    request<{ data: Application }>('GET', getUrl('application', owner, name)),
  updateApplication: (owner: string, name: string, app: Application) =>
    request<{ data: string }>('POST', updateUrl('application', owner, name), app),

  // Providers
  getProviders: (owner: string) =>
    request<ListResponse<Provider>>('GET', listUrl('provider', owner)),
  getProvider: (owner: string, name: string) =>
    request<{ data: Provider }>('GET', getUrl('provider', owner, name)),
  updateProvider: (owner: string, name: string, p: Provider) =>
    request<{ data: string }>('POST', updateUrl('provider', owner, name), p),

  // Roles
  getRoles: (owner: string) =>
    request<ListResponse<Role>>('GET', listUrl('role', owner)),
  getRole: (owner: string, name: string) =>
    request<{ data: Role }>('GET', getUrl('role', owner, name)),
  updateRole: (owner: string, name: string, role: Role) =>
    request<{ data: string }>('POST', updateUrl('role', owner, name), role),

  // Permissions
  getPermissions: (owner: string) =>
    request<ListResponse<Permission>>('GET', listUrl('permission', owner)),
  getPermission: (owner: string, name: string) =>
    request<{ data: Permission }>('GET', getUrl('permission', owner, name)),
  updatePermission: (owner: string, name: string, perm: Permission) =>
    request<{ data: string }>('POST', updateUrl('permission', owner, name), perm),

  // Tokens
  getTokens: (owner: string) =>
    request<ListResponse<Token>>('GET', listUrl('token', owner)),
  deleteToken: (token: Token) =>
    request<{ data: string }>('POST', deleteUrl('token'), token),

  // Sessions
  getSessions: (owner: string) =>
    request<ListResponse<Session>>('GET', listUrl('session', owner)),
  deleteSession: (session: Session) =>
    request<{ data: string }>('POST', deleteUrl('session'), session),

  // Certs
  getCerts: (owner: string) =>
    request<ListResponse<Cert>>('GET', listUrl('cert', owner)),
  getCert: (owner: string, name: string) =>
    request<{ data: Cert }>('GET', getUrl('cert', owner, name)),
  updateCert: (owner: string, name: string, cert: Cert) =>
    request<{ data: string }>('POST', updateUrl('cert', owner, name), cert),

  // Webhooks
  getWebhooks: (owner: string) =>
    request<ListResponse<Webhook>>('GET', listUrl('webhook', owner)),
  getWebhook: (owner: string, name: string) =>
    request<{ data: Webhook }>('GET', getUrl('webhook', owner, name)),
  updateWebhook: (owner: string, name: string, wh: Webhook) =>
    request<{ data: string }>('POST', updateUrl('webhook', owner, name), wh),

  // Groups
  getGroups: (owner: string) =>
    request<ListResponse<Group>>('GET', listUrl('group', owner)),
  getGroup: (owner: string, name: string) =>
    request<{ data: Group }>('GET', getUrl('group', owner, name)),
  updateGroup: (owner: string, name: string, g: Group) =>
    request<{ data: string }>('POST', updateUrl('group', owner, name), g),

  // LDAP
  getLdaps: (owner: string) =>
    request<ListResponse<Ldap>>('GET', listUrl('ldap', owner)),
  getLdap: (owner: string, name: string) =>
    request<{ data: Ldap }>('GET', getUrl('ldap', owner, name)),
  updateLdap: (owner: string, name: string, l: Ldap) =>
    request<{ data: string }>('POST', updateUrl('ldap', owner, name), l),

  // Syncers
  getSyncers: (owner: string) =>
    request<ListResponse<Syncer>>('GET', listUrl('syncer', owner)),
  getSyncer: (owner: string, name: string) =>
    request<{ data: Syncer }>('GET', getUrl('syncer', owner, name)),
  updateSyncer: (owner: string, name: string, s: Syncer) =>
    request<{ data: string }>('POST', updateUrl('syncer', owner, name), s),

  // Enforcers
  getEnforcers: (owner: string) =>
    request<ListResponse<Enforcer>>('GET', listUrl('enforcer', owner)),
  getEnforcer: (owner: string, name: string) =>
    request<{ data: Enforcer }>('GET', getUrl('enforcer', owner, name)),
  updateEnforcer: (owner: string, name: string, e: Enforcer) =>
    request<{ data: string }>('POST', updateUrl('enforcer', owner, name), e),

  // Adapters
  getAdapters: (owner: string) =>
    request<ListResponse<Adapter>>('GET', listUrl('adapter', owner)),
  getAdapter: (owner: string, name: string) =>
    request<{ data: Adapter }>('GET', getUrl('adapter', owner, name)),
  updateAdapter: (owner: string, name: string, a: Adapter) =>
    request<{ data: string }>('POST', updateUrl('adapter', owner, name), a),

  // Models
  getModels: (owner: string) =>
    request<ListResponse<Model>>('GET', listUrl('model', owner)),
  getModel: (owner: string, name: string) =>
    request<{ data: Model }>('GET', getUrl('model', owner, name)),
  updateModel: (owner: string, name: string, m: Model) =>
    request<{ data: string }>('POST', updateUrl('model', owner, name), m),

  // Forms
  getForms: (owner: string) =>
    request<ListResponse<Form>>('GET', listUrl('form', owner)),
  getForm: (owner: string, name: string) =>
    request<{ data: Form }>('GET', getUrl('form', owner, name)),
  updateForm: (owner: string, name: string, f: Form) =>
    request<{ data: string }>('POST', updateUrl('form', owner, name), f),

  // Tickets
  getTickets: (owner: string) =>
    request<ListResponse<Ticket>>('GET', listUrl('ticket', owner)),
  getTicket: (owner: string, name: string) =>
    request<{ data: Ticket }>('GET', getUrl('ticket', owner, name)),
  updateTicket: (owner: string, name: string, t: Ticket) =>
    request<{ data: string }>('POST', updateUrl('ticket', owner, name), t),

  // Sites
  getSites: (owner: string) =>
    request<ListResponse<Site>>('GET', listUrl('site', owner)),
  getSite: (owner: string, name: string) =>
    request<{ data: Site }>('GET', getUrl('site', owner, name)),
  updateSite: (owner: string, name: string, s: Site) =>
    request<{ data: string }>('POST', updateUrl('site', owner, name), s),

  // Invitations
  getInvitations: (owner: string) =>
    request<ListResponse<Invitation>>('GET', listUrl('invitation', owner)),

  // Keys
  getKeys: (owner: string) =>
    request<ListResponse<Key>>('GET', listUrl('key', owner)),
  getKey: (owner: string, name: string) =>
    request<{ data: Key }>('GET', getUrl('key', owner, name)),
  updateKey: (owner: string, name: string, k: Key) =>
    request<{ data: string }>('POST', updateUrl('key', owner, name), k),

  // Servers
  getServers: (owner: string) =>
    request<ListResponse<Server>>('GET', listUrl('server', owner)),
  getServer: (owner: string, name: string) =>
    request<{ data: Server }>('GET', getUrl('server', owner, name)),
  updateServer: (owner: string, name: string, s: Server) =>
    request<{ data: string }>('POST', updateUrl('server', owner, name), s),

  // Captcha
  getCaptchaProvider: (owner: string) =>
    request<ListResponse<CaptchaProvider>>('GET', listUrl('captcha-provider', owner)),
  updateCaptchaProvider: (owner: string, name: string, c: CaptchaProvider) =>
    request<{ data: string }>('POST', updateUrl('captcha-provider', owner, name), c),

  // Verifications
  getVerifications: (owner: string) =>
    request<ListResponse<Verification>>('GET', listUrl('verification', owner)),

  // Resources
  getResources: (owner: string) =>
    request<ListResponse<Resource>>('GET', listUrl('resource', owner)),
  getResource: (owner: string, name: string) =>
    request<{ data: Resource }>('GET', getUrl('resource', owner, name)),
  updateResource: (owner: string, name: string, r: Resource) =>
    request<{ data: string }>('POST', updateUrl('resource', owner, name), r),

  // Records
  getRecords: (owner: string) =>
    request<ListResponse<AuditRecord>>('GET', listUrl('record', owner)),

  // Rules
  getRules: (owner: string) =>
    request<ListResponse<Rule>>('GET', listUrl('rule', owner)),
  getRule: (owner: string, name: string) =>
    request<{ data: Rule }>('GET', getUrl('rule', owner, name)),
  updateRule: (owner: string, name: string, r: Rule) =>
    request<{ data: string }>('POST', updateUrl('rule', owner, name), r),

  // Search (for command palette)
  searchUsers: (q: string) =>
    request<ListResponse<User>>('GET', `/api/get-users?owner=*&q=${encodeURIComponent(q)}`),
  searchOrganizations: (q: string) =>
    request<ListResponse<Organization>>('GET', `/api/get-organizations?owner=admin&q=${encodeURIComponent(q)}`),
  searchApplications: (q: string) =>
    request<ListResponse<Application>>('GET', `/api/get-applications?owner=*&q=${encodeURIComponent(q)}`),

  // Account (current user)
  getAccount: () =>
    request<{ data: User }>('GET', '/api/get-account'),
}
