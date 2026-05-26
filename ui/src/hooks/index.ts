// Admin hooks (react-query against /api/admin/* — for the IAM admin UI itself)
export * from './use-iam'

// Client hook (for consumer apps: 'am I logged in?')
export { useIAMAuth, type IAMUser, type IAMOrg, type UseIAMOptions } from './useIAMAuth'
