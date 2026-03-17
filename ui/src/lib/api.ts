// Typed API client for IAM backend — all calls use cookies (same origin).
// IAM (Casdoor) API pattern:
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

  // Account (current user)
  getAccount: () =>
    request<{ data: User }>('GET', '/api/get-account'),
}
