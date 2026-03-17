import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type {
  User, Organization, Application, Provider, Role,
  Permission, Token, Session, Cert, Webhook,
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
