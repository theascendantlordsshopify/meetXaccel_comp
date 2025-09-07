import React, { useState } from 'react'
import { ChevronLeft, ChevronRight, Clock, Calendar } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { formatDate, formatTime } from '@/utils/date'
import { cn } from '@/utils/cn'

interface TimeSlot {
  start_time: string
  end_time: string
  duration_minutes: number
  available_spots?: number
}

interface TimeSlotPickerProps {
  availableSlots: TimeSlot[]
  selectedDate: Date
  onDateChange: (date: Date) => void
  onSlotSelect: (slot: TimeSlot) => void
  timezone: string
  isLoading?: boolean
  className?: string
}

export function TimeSlotPicker({
  availableSlots,
  selectedDate,
  onDateChange,
  onSlotSelect,
  timezone,
  isLoading = false,
  className,
}: TimeSlotPickerProps) {
  const [currentWeek, setCurrentWeek] = useState(new Date())

  const getWeekDates = (startDate: Date) => {
    const dates = []
    const start = new Date(startDate)
    start.setDate(start.getDate() - start.getDay()) // Start from Sunday
    
    for (let i = 0; i < 7; i++) {
      const date = new Date(start)
      date.setDate(start.getDate() + i)
      dates.push(date)
    }
    return dates
  }

  const navigateWeek = (direction: 'prev' | 'next') => {
    const newWeek = new Date(currentWeek)
    newWeek.setDate(newWeek.getDate() + (direction === 'next' ? 7 : -7))
    setCurrentWeek(newWeek)
    
    // Update selected date to first available day of new week
    const weekDates = getWeekDates(newWeek)
    const firstAvailableDate = weekDates.find(date => date >= new Date())
    if (firstAvailableDate) {
      onDateChange(firstAvailableDate)
    }
  }

  const weekDates = getWeekDates(currentWeek)
  const today = new Date()

  return (
    <div className={cn('grid grid-cols-1 lg:grid-cols-2 gap-6', className)}>
      {/* Date Picker */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-secondary-900">
              Select Date
            </h3>
            <div className="flex items-center space-x-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigateWeek('prev')}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigateWeek('next')}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-7 gap-1 mb-2">
            {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((day) => (
              <div key={day} className="text-center text-xs font-medium text-secondary-500 py-2">
                {day}
              </div>
            ))}
          </div>
          
          <div className="grid grid-cols-7 gap-1">
            {weekDates.map((date) => {
              const isSelected = date.toDateString() === selectedDate.toDateString()
              const isToday = date.toDateString() === today.toDateString()
              const isPast = date < today && !isToday
              
              return (
                <button
                  key={date.toISOString()}
                  onClick={() => !isPast && onDateChange(date)}
                  disabled={isPast}
                  className={cn(
                    'aspect-square text-sm rounded-md transition-colors',
                    'hover:bg-primary-50 focus:outline-none focus:ring-2 focus:ring-primary-500',
                    isSelected && 'bg-primary-600 text-white',
                    isToday && !isSelected && 'ring-1 ring-primary-300',
                    isPast && 'opacity-50 cursor-not-allowed',
                    !isSelected && !isPast && 'text-secondary-900'
                  )}
                >
                  {date.getDate()}
                </button>
              )
            })}
          </div>
          
          <div className="mt-4 text-center">
            <p className="text-sm text-secondary-600">
              {formatDate(selectedDate, 'EEEE, MMMM dd, yyyy')}
            </p>
            <p className="text-xs text-secondary-500 mt-1">
              {timezone}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Time Slots */}
      <Card>
        <CardHeader>
          <h3 className="text-lg font-semibold text-secondary-900">
            Available Times
          </h3>
          <p className="text-sm text-secondary-600">
            {formatDate(selectedDate, 'EEEE, MMMM dd')}
          </p>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner size="md" />
            </div>
          ) : availableSlots.length === 0 ? (
            <div className="text-center py-8">
              <Clock className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                No Available Times
              </h3>
              <p className="text-secondary-600 mb-4">
                There are no available time slots for this date.
              </p>
              <Button
                variant="outline"
                onClick={() => {
                  const tomorrow = new Date(selectedDate)
                  tomorrow.setDate(tomorrow.getDate() + 1)
                  onDateChange(tomorrow)
                }}
              >
                Try Tomorrow
              </Button>
            </div>
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {availableSlots.map((slot, index) => (
                <Button
                  key={index}
                  variant="outline"
                  onClick={() => onSlotSelect(slot)}
                  className="w-full h-12 justify-between hover:bg-primary-50 hover:border-primary-300 transition-colors"
                >
                  <span>{formatTime(slot.start_time)}</span>
                  {slot.available_spots !== undefined && slot.available_spots < 10 && (
                    <span className="text-xs text-warning-600">
                      {slot.available_spots} spots left
                    </span>
                  )}
                </Button>
              ))}
            </div>
          )}
          
          {availableSlots.length > 0 && (
            <div className="mt-4 text-center">
              <p className="text-xs text-secondary-500">
                {availableSlots.length} time{availableSlots.length !== 1 ? 's' : ''} available
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}