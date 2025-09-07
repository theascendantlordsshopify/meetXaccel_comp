import React, { useState } from 'react'
import { Calendar, ChevronLeft, ChevronRight } from 'lucide-react'
import { cn } from '@/utils/cn'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { useClickOutside } from '@/hooks/useClickOutside'
import { formatDate } from '@/utils/date'

interface DatePickerProps {
  value?: Date
  onChange: (date: Date | undefined) => void
  placeholder?: string
  label?: string
  error?: string
  disabled?: boolean
  required?: boolean
  minDate?: Date
  maxDate?: Date
  className?: string
}

export function DatePicker({
  value,
  onChange,
  placeholder = 'Select date...',
  label,
  error,
  disabled = false,
  required = false,
  minDate,
  maxDate,
  className,
}: DatePickerProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [viewDate, setViewDate] = useState(value || new Date())
  
  const pickerRef = useClickOutside<HTMLDivElement>(() => setIsOpen(false))

  const handleDateSelect = (date: Date) => {
    onChange(date)
    setIsOpen(false)
  }

  const handleClear = () => {
    onChange(undefined)
    setIsOpen(false)
  }

  const isDateDisabled = (date: Date) => {
    if (minDate && date < minDate) return true
    if (maxDate && date > maxDate) return true
    return false
  }

  const getDaysInMonth = (date: Date) => {
    const year = date.getFullYear()
    const month = date.getMonth()
    const firstDay = new Date(year, month, 1)
    const lastDay = new Date(year, month + 1, 0)
    const daysInMonth = lastDay.getDate()
    const startingDayOfWeek = firstDay.getDay()

    const days = []
    
    // Add empty cells for days before the first day of the month
    for (let i = 0; i < startingDayOfWeek; i++) {
      days.push(null)
    }
    
    // Add days of the month
    for (let day = 1; day <= daysInMonth; day++) {
      days.push(new Date(year, month, day))
    }
    
    return days
  }

  const navigateMonth = (direction: 'prev' | 'next') => {
    const newDate = new Date(viewDate)
    if (direction === 'prev') {
      newDate.setMonth(newDate.getMonth() - 1)
    } else {
      newDate.setMonth(newDate.getMonth() + 1)
    }
    setViewDate(newDate)
  }

  const days = getDaysInMonth(viewDate)
  const weekDays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

  return (
    <div className={cn('relative', className)}>
      <Input
        label={label}
        value={value ? formatDate(value) : ''}
        placeholder={placeholder}
        readOnly
        onClick={() => !disabled && setIsOpen(true)}
        rightIcon={<Calendar className="h-4 w-4" />}
        error={error}
        disabled={disabled}
        required={required}
        className="cursor-pointer"
      />

      {isOpen && (
        <div
          ref={pickerRef}
          className="absolute z-50 mt-1 bg-white rounded-lg shadow-strong border border-secondary-200 p-4 min-w-[280px]"
        >
          {/* Header */}
          <div className="flex items-center justify-between mb-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigateMonth('prev')}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            
            <h3 className="text-sm font-medium text-secondary-900">
              {viewDate.toLocaleDateString('en-US', { 
                month: 'long', 
                year: 'numeric' 
              })}
            </h3>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigateMonth('next')}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>

          {/* Calendar Grid */}
          <div className="grid grid-cols-7 gap-1 mb-2">
            {weekDays.map((day) => (
              <div
                key={day}
                className="text-xs font-medium text-secondary-500 text-center py-2"
              >
                {day}
              </div>
            ))}
          </div>

          <div className="grid grid-cols-7 gap-1">
            {days.map((day, index) => (
              <div key={index} className="aspect-square">
                {day && (
                  <button
                    type="button"
                    onClick={() => handleDateSelect(day)}
                    disabled={isDateDisabled(day)}
                    className={cn(
                      'w-full h-full text-sm rounded-md transition-colors',
                      'hover:bg-primary-50 focus:outline-none focus:ring-2 focus:ring-primary-500',
                      value && day.toDateString() === value.toDateString()
                        ? 'bg-primary-600 text-white'
                        : 'text-secondary-900',
                      isDateDisabled(day) && 'opacity-50 cursor-not-allowed',
                      day.toDateString() === new Date().toDateString() && 
                        'ring-1 ring-primary-300'
                    )}
                  >
                    {day.getDate()}
                  </button>
                )}
              </div>
            ))}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-secondary-200">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleClear}
            >
              Clear
            </Button>
            
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsOpen(false)}
            >
              Close
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}