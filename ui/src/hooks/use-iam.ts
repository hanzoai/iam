import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type {
  User, Organization, Application, Provider, Role,
  Permission, Token, Session, Cert, Webhook,
  Group, Ldap, Syncer, Enforcer, Adapter, Model, Form,
  Ticket, Site, Invitation, Key, Server, CaptchaProvider,
  Verification, Resource, AuditRecord, Rule,
} from '../lib/api'

// Current account
export function useAccount() {
  return useQuery({
    queryKey: ['account'],
    queryFn: () => api.getAccount().then(r => r.data),
  })
}

// Users
export function useUsers(owner: string) {
  return useQuery({
    queryKey: ['users', owner],
    queryFn: () => api.getUsers(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useUser(owner: string, name: string) {
  return useQuery({
    queryKey: ['user', owner, name],
    queryFn: () => api.getUser(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

export function useUpdateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (u: User) => api.updateUser(u.owner, u.name, u),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
}

// Organizations
export function useOrganizations(owner: string) {
  return useQuery({
    queryKey: ['organizations', owner],
    queryFn: () => api.getOrganizations(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useOrganization(owner: string, name: string) {
  return useQuery({
    queryKey: ['organization', owner, name],
    queryFn: () => api.getOrganization(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

export function useUpdateOrganization() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (o: Organization) => api.updateOrganization(o.owner, o.name, o),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['organizations'] }),
  })
}

// Applications
export function useApplications(owner: string) {
  return useQuery({
    queryKey: ['applications', owner],
    queryFn: () => api.getApplications(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useApplication(owner: string, name: string) {
  return useQuery({
    queryKey: ['application', owner, name],
    queryFn: () => api.getApplication(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

export function useUpdateApplication() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (a: Application) => api.updateApplication(a.owner, a.name, a),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['applications'] }),
  })
}

// Providers
export function useProviders(owner: string) {
  return useQuery({
    queryKey: ['providers', owner],
    queryFn: () => api.getProviders(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useProvider(owner: string, name: string) {
  return useQuery({
    queryKey: ['provider', owner, name],
    queryFn: () => api.getProvider(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Roles
export function useRoles(owner: string) {
  return useQuery({
    queryKey: ['roles', owner],
    queryFn: () => api.getRoles(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useRole(owner: string, name: string) {
  return useQuery({
    queryKey: ['role', owner, name],
    queryFn: () => api.getRole(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Permissions
export function usePermissions(owner: string) {
  return useQuery({
    queryKey: ['permissions', owner],
    queryFn: () => api.getPermissions(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

// Tokens
export function useTokens(owner: string) {
  return useQuery({
    queryKey: ['tokens', owner],
    queryFn: () => api.getTokens(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useDeleteToken() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (t: Token) => api.deleteToken(t),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tokens'] }),
  })
}

// Sessions
export function useSessions(owner: string) {
  return useQuery({
    queryKey: ['sessions', owner],
    queryFn: () => api.getSessions(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useDeleteSession() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (s: Session) => api.deleteSession(s),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
  })
}

// Certs
export function useCerts(owner: string) {
  return useQuery({
    queryKey: ['certs', owner],
    queryFn: () => api.getCerts(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useCert(owner: string, name: string) {
  return useQuery({
    queryKey: ['cert', owner, name],
    queryFn: () => api.getCert(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Webhooks
export function useWebhooks(owner: string) {
  return useQuery({
    queryKey: ['webhooks', owner],
    queryFn: () => api.getWebhooks(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useWebhook(owner: string, name: string) {
  return useQuery({
    queryKey: ['webhook', owner, name],
    queryFn: () => api.getWebhook(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Groups
export function useGroups(owner: string) {
  return useQuery({
    queryKey: ['groups', owner],
    queryFn: () => api.getGroups(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useGroup(owner: string, name: string) {
  return useQuery({
    queryKey: ['group', owner, name],
    queryFn: () => api.getGroup(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// LDAP
export function useLdaps(owner: string) {
  return useQuery({
    queryKey: ['ldaps', owner],
    queryFn: () => api.getLdaps(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useLdap(owner: string, name: string) {
  return useQuery({
    queryKey: ['ldap', owner, name],
    queryFn: () => api.getLdap(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Syncers
export function useSyncers(owner: string) {
  return useQuery({
    queryKey: ['syncers', owner],
    queryFn: () => api.getSyncers(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useSyncer(owner: string, name: string) {
  return useQuery({
    queryKey: ['syncer', owner, name],
    queryFn: () => api.getSyncer(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Enforcers
export function useEnforcers(owner: string) {
  return useQuery({
    queryKey: ['enforcers', owner],
    queryFn: () => api.getEnforcers(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useEnforcer(owner: string, name: string) {
  return useQuery({
    queryKey: ['enforcer', owner, name],
    queryFn: () => api.getEnforcer(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Adapters
export function useAdapters(owner: string) {
  return useQuery({
    queryKey: ['adapters', owner],
    queryFn: () => api.getAdapters(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useAdapter(owner: string, name: string) {
  return useQuery({
    queryKey: ['adapter', owner, name],
    queryFn: () => api.getAdapter(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Models
export function useModels(owner: string) {
  return useQuery({
    queryKey: ['models', owner],
    queryFn: () => api.getModels(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useModel(owner: string, name: string) {
  return useQuery({
    queryKey: ['model', owner, name],
    queryFn: () => api.getModel(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Forms
export function useForms(owner: string) {
  return useQuery({
    queryKey: ['forms', owner],
    queryFn: () => api.getForms(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useForm(owner: string, name: string) {
  return useQuery({
    queryKey: ['form', owner, name],
    queryFn: () => api.getForm(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Tickets
export function useTickets(owner: string) {
  return useQuery({
    queryKey: ['tickets', owner],
    queryFn: () => api.getTickets(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useTicket(owner: string, name: string) {
  return useQuery({
    queryKey: ['ticket', owner, name],
    queryFn: () => api.getTicket(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Sites
export function useSites(owner: string) {
  return useQuery({
    queryKey: ['sites', owner],
    queryFn: () => api.getSites(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useSite(owner: string, name: string) {
  return useQuery({
    queryKey: ['site', owner, name],
    queryFn: () => api.getSite(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Invitations
export function useInvitations(owner: string) {
  return useQuery({
    queryKey: ['invitations', owner],
    queryFn: () => api.getInvitations(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

// Keys
export function useKeys(owner: string) {
  return useQuery({
    queryKey: ['keys', owner],
    queryFn: () => api.getKeys(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useKey(owner: string, name: string) {
  return useQuery({
    queryKey: ['key', owner, name],
    queryFn: () => api.getKey(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Servers
export function useServers(owner: string) {
  return useQuery({
    queryKey: ['servers', owner],
    queryFn: () => api.getServers(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useServer(owner: string, name: string) {
  return useQuery({
    queryKey: ['server', owner, name],
    queryFn: () => api.getServer(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Captcha
export function useCaptchaProviders(owner: string) {
  return useQuery({
    queryKey: ['captcha-providers', owner],
    queryFn: () => api.getCaptchaProvider(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

// Verifications
export function useVerifications(owner: string) {
  return useQuery({
    queryKey: ['verifications', owner],
    queryFn: () => api.getVerifications(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

// Resources
export function useResources(owner: string) {
  return useQuery({
    queryKey: ['resources', owner],
    queryFn: () => api.getResources(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useResource(owner: string, name: string) {
  return useQuery({
    queryKey: ['resource', owner, name],
    queryFn: () => api.getResource(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}

// Records
export function useRecords(owner: string) {
  return useQuery({
    queryKey: ['records', owner],
    queryFn: () => api.getRecords(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

// Rules
export function useRules(owner: string) {
  return useQuery({
    queryKey: ['rules', owner],
    queryFn: () => api.getRules(owner).then(r => r.data ?? []),
    enabled: !!owner,
  })
}

export function useRule(owner: string, name: string) {
  return useQuery({
    queryKey: ['rule', owner, name],
    queryFn: () => api.getRule(owner, name).then(r => r.data),
    enabled: !!owner && !!name,
  })
}
