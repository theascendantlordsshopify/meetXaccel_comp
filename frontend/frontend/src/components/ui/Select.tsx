import React, { useState, useRef } from 'react'
import { ChevronDown, Check, X } from 'lucide-react'
import { cn } from '@/utils/cn'
import { useClickOutside } from '@/hooks/useClickOutside'
import type { SelectProps } from '@/types/ui'

export function Select({
  options,
  value,
  defaultValue,
  onChange,
  placeholder = 'Select an option...',
  label,
  error,
  helpText,
  disabled = false,
  required = false,
  multiple = false,
  searchable = false,
  clearable = false,
  loading = false,
  className,
  name,
  id,
  'data-testid': testId,
}: SelectProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const selectRef = useClickOutside<HTMLDivElement>(() => setIsOpen(false))
  const searchInputRef = useRef<HTMLInputElement>(null)

  const currentValue = value !== undefined ? value : defaultValue
  const isMultiple = multiple
  const selectedValues = isMultiple 
    ? (Array.isArray(currentValue) ? currentValue : [])
    : (currentValue !== undefined ? [currentValue] : [])

  const filteredOptions = searchable && searchQuery
    ? options.filter(option => 
        option.label.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : options

  const selectedOptions = options.filter(option => 
    selectedValues.includes(option.value)
  )

  const handleSelect = (optionValue: string | number) => {
    if (disabled) return

    let newValue: string | number | string[]
    
    if (isMultiple) {
      const currentArray = Array.isArray(currentValue) ? currentValue : []
      if (currentArray.includes(optionValue)) {
        newValue = currentArray.filter(v => v !== optionValue)
      } else {
        newValue = [...currentArray, optionValue]
      }
    } else {
      newValue = optionValue
      setIsOpen(false)
    }

    onChange?.(newValue)
  }

  const handleClear = () => {
    if (disabled) return
    onChange?.(isMultiple ? [] : '')
  }

  const handleOpen = () => {
    if (disabled) return
    setIsOpen(true)
    if (searchable && searchInputRef.current) {
      setTimeout(() => searchInputRef.current?.focus(), 0)
    }
  }

  const displayValue = () => {
    if (selectedOptions.length === 0) {
      return placeholder
    }
    
    if (isMultiple) {
      if (selectedOptions.length === 1) {
        return selectedOptions[0].label
      }
      return `${selectedOptions.length} selected`
    }
    
    return selectedOptions[0]?.label || placeholder
  }

  const selectId = id || name

  return (
    <div className="form-group">
      {label && (
        <label htmlFor={selectId} className="form-label">
          {label}
          {required && <span className="text-error-500 ml-1">*</span>}
        </label>
      )}
      
      <div ref={selectRef} className="relative">
        <button
          type="button"
          id={selectId}
          onClick={handleOpen}
          disabled={disabled || loading}
          data-testid={testId}
          className={cn(
            'input w-full flex items-center justify-between text-left',
            error && 'border-error-300 focus-visible:ring-error-500',
            disabled && 'bg-secondary-50 cursor-not-allowed',
            selectedOptions.length === 0 && 'text-secondary-500',
            className
          )}
        >
          <span className="block truncate">{displayValue()}</span>
          
          <div className="flex items-center space-x-1">
            {clearable && selectedOptions.length > 0 && !disabled && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  handleClear()
                }}
                className="p-0.5 rounded hover:bg-secondary-100 text-secondary-400 hover:text-secondary-600"
              >
                <X className="h-3 w-3" />
              </button>
            )}
            
            {loading ? (
              <div className="animate-spin h-4 w-4 text-secondary-400">
                <svg fill="none" viewBox="0 0 24 24">
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
              </div>
            ) : (
              <ChevronDown className={cn(
                'h-4 w-4 text-secondary-400 transition-transform duration-200',
                isOpen && 'transform rotate-180'
              )} />
            )}
          </div>
        </button>

        {/* Dropdown */}
        {isOpen && (
          <div className="absolute z-10 mt-1 w-full bg-white shadow-strong rounded-lg border border-secondary-200 py-1 max-h-60 overflow-auto">
            {searchable && (
              <div className="px-3 py-2 border-b border-secondary-100">
                <input
                  ref={searchInputRef}
                  type="text"
                  placeholder="Search options..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full px-2 py-1 text-sm border border-secondary-200 rounded focus:outline-none focus:ring-1 focus:ring-primary-500 focus:border-primary-500"
                />
              </div>
            )}
            
            {filteredOptions.length === 0 ? (
              <div className="px-3 py-2 text-sm text-secondary-500">
                {searchQuery ? 'No options found' : 'No options available'}
              </div>
            ) : (
              filteredOptions.map((option) => {
                const isSelected = selectedValues.includes(option.value)
                
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => handleSelect(option.value)}
                    disabled={option.disabled}
                    className={cn(
                      'w-full px-3 py-2 text-left text-sm hover:bg-secondary-50 focus:outline-none focus:bg-secondary-50 flex items-center justify-between',
                      isSelected && 'bg-primary-50 text-primary-900',
                      option.disabled && 'opacity-50 cursor-not-allowed'
                    )}
                  >
                    <div className="flex items-center space-x-2">
                      {option.icon && <span className="flex-shrink-0">{option.icon}</span>}
                      <div>
                        <div>{option.label}</div>
                        {option.description && (
                          <div className="text-xs text-secondary-500">{option.description}</div>
                        )}
                      </div>
                    </div>
                    
                    {isSelected && (
                      <Check className="h-4 w-4 text-primary-600" />
                    )}
                  </button>
                )
              })
            )}
          </div>
        )}
      </div>
      
      {error && <p className="form-error">{error}</p>}
      {helpText && !error && <p className="form-help">{helpText}</p>}
    </div>
  )
}