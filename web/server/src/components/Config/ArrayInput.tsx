interface ArrayInputProps {
  values: string[]
  onChange: (values: string[]) => void
  placeholder?: string
  label?: string
}

export function ArrayInput({ values, onChange, placeholder = 'Enter value...', label }: ArrayInputProps) {
  const addItem = () => {
    onChange([...values, ''])
  }

  const updateItem = (index: number, value: string) => {
    const updated = [...values]
    updated[index] = value
    onChange(updated)
  }

  const removeItem = (index: number) => {
    onChange(values.filter((_, i) => i !== index))
  }

  return (
    <div className="space-y-2">
      {label && <label className="block text-sm font-medium text-gray-300">{label}</label>}
      {values.map((value, index) => (
        <div key={index} className="flex gap-2">
          <input
            type="text"
            value={value}
            onChange={(e) => updateItem(index, e.target.value)}
            placeholder={placeholder}
            className="input flex-1"
          />
          <button
            type="button"
            onClick={() => removeItem(index)}
            className="btn btn-ghost text-bifrost-error hover:bg-bifrost-error/10"
            aria-label="Remove item"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </button>
        </div>
      ))}
      <button type="button" onClick={addItem} className="btn btn-secondary text-sm">
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
        </svg>
        Add
      </button>
    </div>
  )
}
