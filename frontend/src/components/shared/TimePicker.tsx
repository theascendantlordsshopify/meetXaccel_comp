import React, { useState } from 'react'
import { Clock } from 'lucide-react'
import { cn } from '@/utils/cn'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'

interface TimePickerProps {
  value?: string // HH:MM format
  onChange: (time: string) => void
  label?: string
  error?: string
  disabled?: boolean
  required?: boolean
  format?: '12h' | '24h'
  step?: number // minutes
  className?: string
}

export function TimePicker({
  value,
  onChange,
  label,
  error,
  disabled = false,
  required = false,
  format = '12h',
  step = 15,
  className,
}: TimePickerProps) {
  const [isOpen, setIsOpen] = useState(false)

  const generateTimeOptions = () => {
    const options = []
    const totalMinutes = 24 * 60
    
    for (let minutes = 0; minutes < totalMinutes; minutes += step) {
      const hours = Math.floor(minutes / 60)
      const mins = minutes % 60
      
      const time24 = `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`
      
      let displayTime = time24
      if (format === '12h') {
        const hour12 = hours === 0 ? 12 : hours > 12 ? hours - 12 : hours
        const ampm = hours >= 12 ? 'PM' : 'AM'
        displayTime = `${hour12}:${mins.toString().padStart(2, '0')} ${ampm}`
      }
      
      options.push({
        value: time24,
        label: displayTime,
      })
    }
    
    return options
  }

  const timeOptions = generateTimeOptions()
  
  const formatDisplayValue = (time: string) => {
    if (!time) return ''
    
    if (format === '12h') {
      const [hours, minutes] = time.split(':').map(Number)
      const hour12 = hours === 0 ? 12 : hours > 12 ? hours - 12 : hours
      const ampm = hours >= 12 ? 'PM' : 'AM'
      return `${hour12}:${minutes.toString().padStart(2, '0')} ${ampm}`
    }
    
    return time
  }

  return (
    <div className={className}>
      <Select
        label={label}
        options={timeOptions}
        value={value}
        onChange={(selectedValue) => onChange(selectedValue as string)}
        placeholder="Select time..."
        error={error}
        disabled={disabled}
        required={required}
        searchable
      />
    </div>
  )
}