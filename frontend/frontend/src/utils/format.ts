/**
 * Format currency values
 */
export function formatCurrency(
  amount: number,
  currency: string = 'USD',
  locale: string = 'en-US'
): string {
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency,
  }).format(amount)
}

/**
 * Format large numbers with abbreviations (K, M, B)
 */
export function formatCompactNumber(num: number): string {
  if (num < 1000) return num.toString()
  
  const units = ['', 'K', 'M', 'B', 'T']
  const unitIndex = Math.floor(Math.log10(Math.abs(num)) / 3)
  const unitValue = Math.pow(1000, unitIndex)
  const formattedNum = (num / unitValue).toFixed(1)
  
  return `${formattedNum}${units[unitIndex]}`
}

/**
 * Format phone number
 */
export function formatPhoneNumber(phone: string): string {
  // Remove all non-digit characters
  const digits = phone.replace(/\D/g, '')
  
  // Format US phone numbers
  if (digits.length === 10) {
    return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`
  }
  
  if (digits.length === 11 && digits.startsWith('1')) {
    return `+1 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`
  }
  
  // For international numbers, just add spaces
  if (digits.length > 10) {
    return `+${digits.slice(0, -10)} ${digits.slice(-10, -7)} ${digits.slice(-7, -4)} ${digits.slice(-4)}`
  }
  
  return phone
}

/**
 * Format status for display
 */
export function formatStatus(status: string): string {
  return status
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

/**
 * Format event type duration
 */
export function formatEventDuration(duration: number): string {
  if (duration < 60) {
    return `${duration} min`
  }
  
  const hours = Math.floor(duration / 60)
  const minutes = duration % 60
  
  if (minutes === 0) {
    return `${hours} hr`
  }
  
  return `${hours} hr ${minutes} min`
}

/**
 * Format booking status with color
 */
export function getStatusColor(status: string): string {
  const statusColors: Record<string, string> = {
    confirmed: 'success',
    cancelled: 'error',
    completed: 'secondary',
    rescheduled: 'warning',
    no_show: 'error',
    pending: 'warning',
    active: 'success',
    inactive: 'secondary',
    failed: 'error',
    succeeded: 'success',
    sent: 'success',
    delivered: 'success',
    bounced: 'error',
    opened: 'info',
    clicked: 'info',
  }
  
  return statusColors[status] || 'secondary'
}

/**
 * Format integration provider name
 */
export function formatProviderName(provider: string): string {
  const providerNames: Record<string, string> = {
    google: 'Google',
    google_calendar: 'Google Calendar',
    google_meet: 'Google Meet',
    outlook: 'Microsoft Outlook',
    microsoft_teams: 'Microsoft Teams',
    zoom: 'Zoom',
    apple: 'Apple Calendar',
    webex: 'Cisco Webex',
  }
  
  return providerNames[provider] || formatStatus(provider)
}

/**
 * Format workflow trigger
 */
export function formatWorkflowTrigger(trigger: string): string {
  const triggerNames: Record<string, string> = {
    booking_created: 'Booking Created',
    booking_cancelled: 'Booking Cancelled',
    booking_completed: 'Booking Completed',
    before_meeting: 'Before Meeting',
    after_meeting: 'After Meeting',
  }
  
  return triggerNames[trigger] || formatStatus(trigger)
}

/**
 * Format notification type
 */
export function formatNotificationType(type: string): string {
  const typeNames: Record<string, string> = {
    email: 'Email',
    sms: 'SMS',
    booking_confirmation: 'Booking Confirmation',
    booking_reminder: 'Booking Reminder',
    booking_cancellation: 'Booking Cancellation',
    booking_rescheduled: 'Booking Rescheduled',
    follow_up: 'Follow-up',
    custom: 'Custom',
  }
  
  return typeNames[type] || formatStatus(type)
}

/**
 * Format location type
 */
export function formatLocationType(type: string): string {
  const locationTypes: Record<string, string> = {
    video_call: 'Video Call',
    phone_call: 'Phone Call',
    in_person: 'In Person',
    custom: 'Custom',
  }
  
  return locationTypes[type] || formatStatus(type)
}

/**
 * Format question type
 */
export function formatQuestionType(type: string): string {
  const questionTypes: Record<string, string> = {
    text: 'Text Input',
    textarea: 'Long Text',
    select: 'Single Select',
    multiselect: 'Multiple Select',
    checkbox: 'Checkbox',
    radio: 'Radio Buttons',
    email: 'Email',
    phone: 'Phone Number',
    number: 'Number',
    date: 'Date',
    time: 'Time',
    url: 'URL',
  }
  
  return questionTypes[type] || formatStatus(type)
}

/**
 * Format bytes to human readable size
 */
export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes'
  
  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
  
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}

/**
 * Format success rate as percentage
 */
export function formatSuccessRate(successful: number, total: number): string {
  if (total === 0) return '0%'
  const rate = (successful / total) * 100
  return `${rate.toFixed(1)}%`
}

/**
 * Format execution time
 */
export function formatExecutionTime(seconds: number): string {
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)}ms`
  }
  
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`
  }
  
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  
  if (remainingSeconds === 0) {
    return `${minutes}m`
  }
  
  return `${minutes}m ${remainingSeconds.toFixed(1)}s`
}

/**
 * Format API call count
 */
export function formatApiCalls(count: number): string {
  if (count < 1000) return count.toString()
  
  if (count < 1000000) {
    return `${(count / 1000).toFixed(1)}K`
  }
  
  return `${(count / 1000000).toFixed(1)}M`
}

/**
 * Format health status
 */
export function formatHealthStatus(status: string): {
  label: string
  color: string
  icon: string
} {
  const statusMap: Record<string, { label: string; color: string; icon: string }> = {
    healthy: { label: 'Healthy', color: 'success', icon: 'CheckCircle' },
    degraded: { label: 'Degraded', color: 'warning', icon: 'AlertTriangle' },
    unhealthy: { label: 'Unhealthy', color: 'error', icon: 'XCircle' },
    unknown: { label: 'Unknown', color: 'secondary', icon: 'HelpCircle' },
  }
  
  return statusMap[status] || statusMap.unknown
}

/**
 * Format list with proper grammar
 */
export function formatList(items: string[], conjunction: string = 'and'): string {
  if (items.length === 0) return ''
  if (items.length === 1) return items[0]
  if (items.length === 2) return `${items[0]} ${conjunction} ${items[1]}`
  
  const lastItem = items[items.length - 1]
  const otherItems = items.slice(0, -1)
  
  return `${otherItems.join(', ')}, ${conjunction} ${lastItem}`
}