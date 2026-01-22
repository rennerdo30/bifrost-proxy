import { useState, KeyboardEvent } from 'react'

interface FormTagInputProps {
  label: string
  description?: string
  error?: string
  value: string[]
  onChange: (value: string[]) => void
  placeholder?: string
  disabled?: boolean
}

export function FormTagInput({
  label,
  description,
  error,
  value,
  onChange,
  placeholder = 'Type and press Enter',
  disabled = false,
}: FormTagInputProps) {
  const [inputValue, setInputValue] = useState('')

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && inputValue.trim()) {
      e.preventDefault()
      if (!value.includes(inputValue.trim())) {
        onChange([...value, inputValue.trim()])
      }
      setInputValue('')
    } else if (e.key === 'Backspace' && !inputValue && value.length > 0) {
      onChange(value.slice(0, -1))
    }
  }

  const removeTag = (index: number) => {
    onChange(value.filter((_, i) => i !== index))
  }

  return (
    <div className="space-y-1">
      <label className="block text-sm font-medium text-bifrost-muted">{label}</label>
      {description && (
        <p className="text-xs text-bifrost-muted/70">{description}</p>
      )}
      <div
        className={`min-h-[42px] p-2 rounded-lg border bg-bifrost-card flex flex-wrap gap-2 items-center ${
          error ? 'border-bifrost-error' : 'border-bifrost-border'
        } focus-within:ring-2 focus-within:ring-bifrost-accent focus-within:border-bifrost-accent`}
      >
        {value.map((tag, index) => (
          <span
            key={index}
            className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-bifrost-accent/20 text-bifrost-accent rounded"
          >
            {tag}
            {!disabled && (
              <button
                type="button"
                onClick={() => removeTag(index)}
                className="hover:text-bifrost-error"
              >
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </span>
        ))}
        <input
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={value.length === 0 ? placeholder : ''}
          disabled={disabled}
          className="flex-1 min-w-[120px] bg-transparent border-none outline-none text-sm text-bifrost-text placeholder-bifrost-muted"
        />
      </div>
      {error && (
        <p className="text-xs text-bifrost-error">{error}</p>
      )}
    </div>
  )
}
