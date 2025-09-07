import { format, parseISO, isValid, addDays, subDays, startOfWeek, endOfWeek, startOfMonth, endOfMonth, isSameDay, isToday, isTomorrow, isYesterday, formatDistanceToNow, addMinutes, differenceInMinutes } from 'date-fns'

/**
 * Format a date string or Date object
 */
export function formatDate(date: string | Date, formatStr = 'MMM dd, yyyy'): string {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    if (!isValid(dateObj)) return 'Invalid date'
    return format(dateObj, formatStr)
  } catch {
    return 'Invalid date'
  }
}

/**
 * Format a time string or Date object
 */
export function formatTime(date: string | Date, formatStr = 'h:mm a'): string {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    if (!isValid(dateObj)) return 'Invalid time'
    return format(dateObj, formatStr)
  } catch {
    return 'Invalid time'
  }
}

/**
 * Format a datetime string or Date object
 */
export function formatDateTime(date: string | Date, formatStr = 'MMM dd, yyyy h:mm a'): string {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    if (!isValid(dateObj)) return 'Invalid datetime'
    return format(dateObj, formatStr)
  } catch {
    return 'Invalid datetime'
  }
}

/**
 * Format relative time (e.g., "2 hours ago", "in 3 days")
 */
export function formatRelativeTime(date: string | Date): string {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    if (!isValid(dateObj)) return 'Invalid date'
    return formatDistanceToNow(dateObj, { addSuffix: true })
  } catch {
    return 'Invalid date'
  }
}

/**
 * Format duration in minutes to human readable format
 */
export function formatDuration(minutes: number): string {
  if (minutes < 60) {
    return `${minutes} min`
  }
  
  const hours = Math.floor(minutes / 60)
  const remainingMinutes = minutes % 60
  
  if (remainingMinutes === 0) {
    return `${hours} hr`
  }
  
  return `${hours} hr ${remainingMinutes} min`
}

/**
 * Get a user-friendly date label
 */
export function getDateLabel(date: string | Date): string {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    if (!isValid(dateObj)) return 'Invalid date'
    
    if (isToday(dateObj)) return 'Today'
    if (isTomorrow(dateObj)) return 'Tomorrow'
    if (isYesterday(dateObj)) return 'Yesterday'
    
    return formatDate(dateObj, 'EEEE, MMM dd')
  } catch {
    return 'Invalid date'
  }
}

/**
 * Get time zone offset string (e.g., "UTC-5", "UTC+2")
 */
export function getTimezoneOffset(date: Date = new Date()): string {
  const offset = -date.getTimezoneOffset()
  const hours = Math.floor(Math.abs(offset) / 60)
  const minutes = Math.abs(offset) % 60
  const sign = offset >= 0 ? '+' : '-'
  
  return `UTC${sign}${hours.toString().padStart(2, '0')}${minutes > 0 ? `:${minutes.toString().padStart(2, '0')}` : ''}`
}

/**
 * Convert UTC time to local timezone
 */
export function toLocalTime(utcTime: string): Date {
  return parseISO(utcTime)
}

/**
 * Convert local time to UTC
 */
export function toUTCTime(localTime: Date): string {
  return localTime.toISOString()
}

/**
 * Get date range for common periods
 */
export function getDateRange(period: 'today' | 'tomorrow' | 'this_week' | 'next_week' | 'this_month' | 'next_month'): {
  start: Date
  end: Date
} {
  const now = new Date()
  
  switch (period) {
    case 'today':
      return { start: now, end: now }
    case 'tomorrow':
      const tomorrow = addDays(now, 1)
      return { start: tomorrow, end: tomorrow }
    case 'this_week':
      return { start: startOfWeek(now), end: endOfWeek(now) }
    case 'next_week':
      const nextWeek = addDays(now, 7)
      return { start: startOfWeek(nextWeek), end: endOfWeek(nextWeek) }
    case 'this_month':
      return { start: startOfMonth(now), end: endOfMonth(now) }
    case 'next_month':
      const nextMonth = addDays(endOfMonth(now), 1)
      return { start: startOfMonth(nextMonth), end: endOfMonth(nextMonth) }
    default:
      return { start: now, end: now }
  }
}

/**
 * Check if a date is in the past
 */
export function isPastDate(date: string | Date): boolean {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    return isValid(dateObj) && dateObj < new Date()
  } catch {
    return false
  }
}

/**
 * Check if a date is in the future
 */
export function isFutureDate(date: string | Date): boolean {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    return isValid(dateObj) && dateObj > new Date()
  } catch {
    return false
  }
}

/**
 * Get the start and end of a day
 */
export function getDayBounds(date: Date): { start: Date; end: Date } {
  const start = new Date(date)
  start.setHours(0, 0, 0, 0)
  
  const end = new Date(date)
  end.setHours(23, 59, 59, 999)
  
  return { start, end }
}

/**
 * Parse time string (HH:MM) to minutes since midnight
 */
export function timeToMinutes(time: string): number {
  const [hours, minutes] = time.split(':').map(Number)
  return hours * 60 + minutes
}

/**
 * Convert minutes since midnight to time string (HH:MM)
 */
export function minutesToTime(minutes: number): string {
  const hours = Math.floor(minutes / 60)
  const mins = minutes % 60
  return `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`
}

/**
 * Get available time slots for a date range
 */
export function generateTimeSlots(
  startTime: string,
  endTime: string,
  interval: number = 15,
  duration: number = 30
): Array<{ start: string; end: string }> {
  const slots: Array<{ start: string; end: string }> = []
  const startMinutes = timeToMinutes(startTime)
  const endMinutes = timeToMinutes(endTime)
  
  for (let current = startMinutes; current + duration <= endMinutes; current += interval) {
    slots.push({
      start: minutesToTime(current),
      end: minutesToTime(current + duration),
    })
  }
  
  return slots
}

/**
 * Check if two time ranges overlap
 */
export function timeRangesOverlap(
  start1: string,
  end1: string,
  start2: string,
  end2: string
): boolean {
  const start1Minutes = timeToMinutes(start1)
  const end1Minutes = timeToMinutes(end1)
  const start2Minutes = timeToMinutes(start2)
  const end2Minutes = timeToMinutes(end2)
  
  return start1Minutes < end2Minutes && end1Minutes > start2Minutes
}

/**
 * Get day of week name
 */
export function getDayName(dayOfWeek: number): string {
  const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
  return days[dayOfWeek] || 'Unknown'
}

/**
 * Get short day name
 */
export function getShortDayName(dayOfWeek: number): string {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
  return days[dayOfWeek] || 'Unknown'
}

/**
 * Format timezone display name
 */
export function formatTimezone(timezone: string): string {
  try {
    const now = new Date()
    const formatter = new Intl.DateTimeFormat('en', {
      timeZone: timezone,
      timeZoneName: 'short',
    })
    
    const parts = formatter.formatToParts(now)
    const timeZoneName = parts.find(part => part.type === 'timeZoneName')?.value || timezone
    
    return `${timezone.replace('_', ' ')} (${timeZoneName})`
  } catch {
    return timezone
  }
}

/**
 * Get user's timezone
 */
export function getUserTimezone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone
}

/**
 * Check if a time slot is in business hours
 */
export function isBusinessHours(time: string, startHour = 9, endHour = 17): boolean {
  const hour = parseInt(time.split(':')[0])
  return hour >= startHour && hour < endHour
}

/**
 * Add buffer time to a time slot
 */
export function addBufferTime(
  startTime: string,
  endTime: string,
  bufferBefore: number = 0,
  bufferAfter: number = 0
): { start: string; end: string } {
  const startMinutes = timeToMinutes(startTime) - bufferBefore
  const endMinutes = timeToMinutes(endTime) + bufferAfter
  
  return {
    start: minutesToTime(Math.max(0, startMinutes)),
    end: minutesToTime(Math.min(24 * 60 - 1, endMinutes)),
  }
}