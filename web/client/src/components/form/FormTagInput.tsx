import { useState, KeyboardEvent } from 'react'

interface FormTagInputProps {
  label: string
  description?: string
  error?: string
  value: string[]
  onChange: (value: string[]) => void
  placeholder?: string
  disabled?: boolean
  validate?: (value: string) => string | null // Returns error message or null if valid
}

export function FormTagInput({
  label,
  description,
  error,
  value,
  onChange,
  placeholder = 'Type and press Enter',
  disabled = false,
  validate,
}: FormTagInputProps) {
  const [inputValue, setInputValue] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && inputValue.trim()) {
      e.preventDefault()
      const trimmed = inputValue.trim()

      // Run validation if provided
      if (validate) {
        const validationResult = validate(trimmed)
        if (validationResult) {
          setValidationError(validationResult)
          return
        }
      }

      setValidationError(null)
      if (!value.includes(trimmed)) {
        onChange([...value, trimmed])
      }
      setInputValue('')
    } else if (e.key === 'Backspace' && !inputValue && value.length > 0) {
      onChange(value.slice(0, -1))
    }
  }

  const handleInputChange = (newValue: string) => {
    setInputValue(newValue)
    if (validationError) {
      setValidationError(null) // Clear validation error when user starts typing
    }
  }

  const displayError = validationError || error

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
          displayError ? 'border-bifrost-error' : 'border-bifrost-border'
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
                aria-label="Remove tag"
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
          onChange={(e) => handleInputChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={value.length === 0 ? placeholder : ''}
          disabled={disabled}
          className="flex-1 min-w-[120px] bg-transparent border-none outline-none text-sm text-bifrost-text placeholder-bifrost-muted"
        />
      </div>
      {displayError && (
        <p className="text-xs text-bifrost-error">{displayError}</p>
      )}
    </div>
  )
}
