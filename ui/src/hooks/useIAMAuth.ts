'use client'

import { useState, useEffect, useCallback } from 'react'

// ─── Canonical IAM types ───────────────────────────────────────────────

export interface IAMUser {
  id?: string
  name?: string
  email: string
  avatar?: string
}

export interface IAMOrg {
  id: string
  name: string
  slug: string
  role?: string
}

export interface UseIAMOptions {
  /** Override the IAM endpoint. Default: `https://iam.hanzo.ai`. */
  endpoint?: string
  /** Override the sign-in / sign-out portal URL. Default: `https://hanzo.id`. */
  portalUrl?: string
  /** localStorage key for the bearer token. Default: `hanzo-auth-token`. */
  tokenKey?: string
  /** localStorage key for the cached user payload. Default: `hanzo-user`. */
  userKey?: string
  /** localStorage key for the token-expiry timestamp. Default: `hanzo-auth-expires`. */
  expiresKey?: string
  /** Map of IAM group slug → org metadata. Unknown groups are dropped. */
  orgMap?: Record<string, { name: string; slug: string }>
}

const DEFAULT_ORG_MAP: Record<string, { name: string; slug: string }> = {
  hanzo: { name: 'Hanzo AI', slug: 'hanzo' },
  lux: { name: 'Lux Network', slug: 'lux' },
  zoo: { name: 'Zoo Labs', slug: 'zoo' },
  pars: { name: 'Pars', slug: 'pars' },
}

/**
 * useIAMAuth — Canonical Hanzo IAM client hook.
 *
 * Reads JWT from localStorage and fetches user/orgs from the configured IAM
 * endpoint (default `iam.hanzo.ai`). Zero-dependency, works across all apps
 * sharing the IAM domain. Configure endpoint via the `endpoint` option.
 *
 * Drop-in for navigation shells (e.g. `@hanzogui/shell`'s TenantHeader).
 */
export function useIAMAuth(options: UseIAMOptions = {}) {
  const {
    endpoint = 'https://iam.hanzo.ai',
    portalUrl = 'https://hanzo.id',
    tokenKey = 'hanzo-auth-token',
    userKey = 'hanzo-user',
    expiresKey = 'hanzo-auth-expires',
    orgMap = DEFAULT_ORG_MAP,
  } = options

  const [user, setUser] = useState<IAMUser | undefined>(undefined)
  const [organizations, setOrganizations] = useState<IAMOrg[]>([])
  const [currentOrgId, setCurrentOrgId] = useState<string | undefined>(undefined)
  const [token, setToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const storedToken = localStorage.getItem(tokenKey)
      const expires = localStorage.getItem(expiresKey)

      if (!storedToken || (expires && Date.now() > Number(expires))) {
        setLoading(false)
        return
      }

      setToken(storedToken)

      // Try cache first for instant render
      const cached = localStorage.getItem(userKey)
      if (cached) {
        try {
          const u = JSON.parse(cached)
          if (u?.email) {
            setUser({ id: u.id, name: u.displayName || u.name, email: u.email, avatar: u.avatar })
          }
        } catch { /* ignore */ }
      }

      // Fetch fresh from IAM
      const res = await fetch(`${endpoint}/api/userinfo`, {
        headers: { Authorization: `Bearer ${storedToken}` },
      })

      if (res.ok) {
        const info = await res.json()
        const u: IAMUser = {
          id: info.sub || info.id,
          name: info.name || info.displayName,
          email: info.email,
          avatar: info.picture || info.avatar,
        }
        setUser(u)
        localStorage.setItem(userKey, JSON.stringify(info))

        // Build orgs from IAM groups
        const groups: string[] = info.groups || []
        const orgs: IAMOrg[] = groups
          .map((g: string) => {
            const slug = g.toLowerCase().replace(/^\//, '')
            const meta = orgMap[slug]
            return meta ? { id: slug, name: meta.name, slug: meta.slug } : null
          })
          .filter(Boolean) as IAMOrg[]

        if (orgs.length === 0 && u.email) {
          orgs.push({ id: 'personal', name: 'Personal', slug: 'personal' })
        }

        setOrganizations(orgs)
        setCurrentOrgId(orgs[0]?.id)
      }
    } catch { /* silently fail */ } finally {
      setLoading(false)
    }
  }, [endpoint, tokenKey, userKey, expiresKey, orgMap])

  useEffect(() => {
    load()
  }, [load])

  const signOut = useCallback(() => {
    localStorage.removeItem(tokenKey)
    localStorage.removeItem(userKey)
    localStorage.removeItem(expiresKey)
    window.location.href = portalUrl
  }, [tokenKey, userKey, expiresKey, portalUrl])

  const switchOrg = useCallback((orgId: string) => {
    setCurrentOrgId(orgId)
  }, [])

  return { user, organizations, currentOrgId, token, loading, signOut, switchOrg }
}
