import { SelectHTMLAttributes } from 'react'

interface Option {
  value: string
  label: string
}

interface FormSelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'value'> {
  label: string
  description?: string
  error?: string
  value: string
  onChange: (value: string) => void
  options: Option[]
}

export function FormSelect({
  label,
  description,
  error,
  value,
  onChange,
  options,
  className = '',
  ...props
}: FormSelectProps) {
  return (
    <div className="space-y-1">
      <label className="block text-sm font-medium text-bifrost-muted">{label}</label>
      {description && (
        <p className="text-xs text-bifrost-muted/70">{description}</p>
      )}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`input ${error ? 'border-bifrost-error focus:ring-bifrost-error' : ''} ${className}`}
        {...props}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      {error && (
        <p className="text-xs text-bifrost-error">{error}</p>
      )}
    </div>
  )
}
