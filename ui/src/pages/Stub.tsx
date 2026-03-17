import { PageHeader } from '../components/PageHeader'

export function Stub({ title }: { title: string }) {
  return (
    <div>
      <PageHeader title={title} />
      <div style={{
        padding: 24,
        background: '#0a0a0a',
        border: '1px solid #262626',
        borderRadius: 8,
        color: '#525252',
        fontSize: 13,
      }}>
        Coming soon
      </div>
    </div>
  )
}
