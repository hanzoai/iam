import type { CSSProperties, ReactNode } from 'react'

const labelStyle: CSSProperties = {
  fontSize: 12,
  color: '#737373',
  marginBottom: 4,
}

const inputStyle: CSSProperties = {
  width: '100%',
  background: '#0a0a0a',
  border: '1px solid #262626',
  borderRadius: 6,
  padding: '6px 10px',
  color: '#e5e5e5',
  fontSize: 13,
  outline: 'none',
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={labelStyle}>{label}</div>
      {children}
    </div>
  )
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} style={{ ...inputStyle, ...props.style }} />
}

export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      style={{
        ...inputStyle,
        minHeight: 80,
        resize: 'vertical',
        fontFamily: 'monospace',
        ...props.style,
      }}
    />
  )
}

export function Toggle({
  checked,
  onChange,
}: {
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <button
      onClick={() => onChange(!checked)}
      style={{
        width: 36,
        height: 20,
        borderRadius: 10,
        border: 'none',
        background: checked ? '#fd4444' : '#333',
        cursor: 'pointer',
        position: 'relative',
        transition: 'background 0.15s',
      }}
    >
      <span
        style={{
          position: 'absolute',
          top: 2,
          left: checked ? 18 : 2,
          width: 16,
          height: 16,
          borderRadius: 8,
          background: '#fff',
          transition: 'left 0.15s',
        }}
      />
    </button>
  )
}
