import { InputHTMLAttributes } from 'react'

interface FormInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  label: string
  description?: string
  error?: string
  value: string
  onChange: (value: string) => void
}

export function FormInput({
  label,
  description,
  error,
  value,
  onChange,
  className = '',
  ...props
}: FormInputProps) {
  return (
    <div className="space-y-1">
      <label className="block text-sm font-medium text-bifrost-muted">{label}</label>
      {description && (
        <p className="text-xs text-bifrost-muted/70">{description}</p>
      )}
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`input ${error ? 'border-bifrost-error focus:ring-bifrost-error' : ''} ${className}`}
        {...props}
      />
      {error && (
        <p className="text-xs text-bifrost-error">{error}</p>
      )}
    </div>
  )
}
