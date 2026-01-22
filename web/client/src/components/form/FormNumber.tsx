import { InputHTMLAttributes } from 'react'

interface FormNumberProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange' | 'value' | 'type'> {
  label: string
  description?: string
  error?: string
  value: number
  onChange: (value: number) => void
}

export function FormNumber({
  label,
  description,
  error,
  value,
  onChange,
  min,
  max,
  className = '',
  ...props
}: FormNumberProps) {
  return (
    <div className="space-y-1">
      <label className="block text-sm font-medium text-bifrost-muted">{label}</label>
      {description && (
        <p className="text-xs text-bifrost-muted/70">{description}</p>
      )}
      <input
        type="number"
        value={value}
        onChange={(e) => {
          const val = parseInt(e.target.value, 10)
          if (!isNaN(val)) {
            onChange(val)
          }
        }}
        min={min}
        max={max}
        className={`input ${error ? 'border-bifrost-error focus:ring-bifrost-error' : ''} ${className}`}
        {...props}
      />
      {error && (
        <p className="text-xs text-bifrost-error">{error}</p>
      )}
    </div>
  )
}
