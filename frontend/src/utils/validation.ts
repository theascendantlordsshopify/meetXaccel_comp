import { z } from 'zod'

/**
 * Email validation
 */
export function isValidEmail(email: string): boolean {
  const emailSchema = z.string().email()
  return emailSchema.safeParse(email).success
}

/**
 * Phone number validation
 */
export function isValidPhoneNumber(phone: string): boolean {
  const phoneRegex = /^\+?1?\d{9,15}$/
  return phoneRegex.test(phone.replace(/\s/g, ''))
}

/**
 * URL validation
 */
export function isValidUrl(url: string): boolean {
  try {
    new URL(url)
    return true
  } catch {
    return false
  }
}

/**
 * Password strength validation
 */
export function validatePasswordStrength(password: string): {
  isValid: boolean
  score: number
  feedback: string[]
} {
  const feedback: string[] = []
  let score = 0

  // Length check
  if (password.length >= 8) {
    score += 1
  } else {
    feedback.push('Password must be at least 8 characters long')
  }

  // Uppercase check
  if (/[A-Z]/.test(password)) {
    score += 1
  } else {
    feedback.push('Password must contain at least one uppercase letter')
  }

  // Lowercase check
  if (/[a-z]/.test(password)) {
    score += 1
  } else {
    feedback.push('Password must contain at least one lowercase letter')
  }

  // Number check
  if (/\d/.test(password)) {
    score += 1
  } else {
    feedback.push('Password must contain at least one number')
  }

  // Special character check
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    score += 1
  } else {
    feedback.push('Password must contain at least one special character')
  }

  // Common patterns check
  const commonPatterns = ['123', 'abc', 'qwerty', 'password', 'admin']
  const hasCommonPattern = commonPatterns.some(pattern => 
    password.toLowerCase().includes(pattern)
  )
  
  if (hasCommonPattern) {
    score -= 1
    feedback.push('Password contains common patterns that should be avoided')
  }

  return {
    isValid: score >= 4 && feedback.length === 0,
    score: Math.max(0, Math.min(5, score)),
    feedback,
  }
}

/**
 * Timezone validation
 */
export function isValidTimezone(timezone: string): boolean {
  try {
    Intl.DateTimeFormat(undefined, { timeZone: timezone })
    return true
  } catch {
    return false
  }
}

/**
 * Hex color validation
 */
export function isValidHexColor(color: string): boolean {
  const hexRegex = /^#[0-9A-F]{6}$/i
  return hexRegex.test(color)
}

/**
 * Slug validation
 */
export function isValidSlug(slug: string): boolean {
  const slugRegex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
  return slugRegex.test(slug)
}

/**
 * File type validation
 */
export function isValidFileType(file: File, allowedTypes: string[]): boolean {
  return allowedTypes.includes(file.type)
}

/**
 * File size validation
 */
export function isValidFileSize(file: File, maxSizeInBytes: number): boolean {
  return file.size <= maxSizeInBytes
}

/**
 * Time format validation (HH:MM)
 */
export function isValidTimeFormat(time: string): boolean {
  const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/
  return timeRegex.test(time)
}

/**
 * Date format validation (YYYY-MM-DD)
 */
export function isValidDateFormat(date: string): boolean {
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/
  if (!dateRegex.test(date)) return false
  
  const dateObj = parseISO(date)
  return isValid(dateObj)
}

/**
 * Validate time range (start time before end time)
 */
export function isValidTimeRange(startTime: string, endTime: string): boolean {
  if (!isValidTimeFormat(startTime) || !isValidTimeFormat(endTime)) {
    return false
  }
  
  const [startHour, startMin] = startTime.split(':').map(Number)
  const [endHour, endMin] = endTime.split(':').map(Number)
  
  const startMinutes = startHour * 60 + startMin
  const endMinutes = endHour * 60 + endMin
  
  // Allow overnight ranges (end time can be less than start time)
  return startMinutes !== endMinutes
}

/**
 * Validate date range (start date before or equal to end date)
 */
export function isValidDateRange(startDate: string, endDate: string): boolean {
  if (!isValidDateFormat(startDate) || !isValidDateFormat(endDate)) {
    return false
  }
  
  const start = parseISO(startDate)
  const end = parseISO(endDate)
  
  return start <= end
}

/**
 * Validate booking time (must be in the future with minimum notice)
 */
export function isValidBookingTime(
  bookingTime: string,
  minNoticeMinutes: number = 15
): boolean {
  try {
    const bookingDate = parseISO(bookingTime)
    const now = new Date()
    const minBookingTime = addMinutes(now, minNoticeMinutes)
    
    return bookingDate >= minBookingTime
  } catch {
    return false
  }
}

/**
 * Validate webhook URL
 */
export function isValidWebhookUrl(url: string): boolean {
  if (!isValidUrl(url)) return false
  
  try {
    const urlObj = new URL(url)
    return urlObj.protocol === 'https:' || urlObj.protocol === 'http:'
  } catch {
    return false
  }
}

/**
 * Validate JSON string
 */
export function isValidJSON(jsonString: string): boolean {
  try {
    JSON.parse(jsonString)
    return true
  } catch {
    return false
  }
}

/**
 * Sanitize HTML content
 */
export function sanitizeHtml(html: string): string {
  const div = document.createElement('div')
  div.textContent = html
  return div.innerHTML
}

/**
 * Validate organizer slug
 */
export function isValidOrganizerSlug(slug: string): boolean {
  // Must be 3-50 characters, lowercase letters, numbers, and hyphens only
  const slugRegex = /^[a-z0-9-]{3,50}$/
  return slugRegex.test(slug) && !slug.startsWith('-') && !slug.endsWith('-')
}

/**
 * Validate event type slug
 */
export function isValidEventTypeSlug(slug: string): boolean {
  // Must be 3-100 characters, lowercase letters, numbers, and hyphens only
  const slugRegex = /^[a-z0-9-]{3,100}$/
  return slugRegex.test(slug) && !slug.startsWith('-') && !slug.endsWith('-')
}

/**
 * Validate duration (must be between 15 minutes and 8 hours)
 */
export function isValidDuration(duration: number): boolean {
  return duration >= 15 && duration <= 480
}

/**
 * Validate buffer time (must be between 0 and 120 minutes)
 */
export function isValidBufferTime(bufferTime: number): boolean {
  return bufferTime >= 0 && bufferTime <= 120
}

/**
 * Validate attendee count
 */
export function isValidAttendeeCount(count: number, maxAttendees: number): boolean {
  return count >= 1 && count <= maxAttendees
}

/**
 * Validate custom question options
 */
export function validateCustomQuestionOptions(
  questionType: string,
  options: string[]
): { isValid: boolean; error?: string } {
  if (['select', 'multiselect', 'radio'].includes(questionType)) {
    if (!options || options.length < 2) {
      return {
        isValid: false,
        error: 'Select and radio questions must have at least 2 options',
      }
    }
    
    // Check for duplicate options
    const uniqueOptions = new Set(options.map(opt => opt.trim().toLowerCase()))
    if (uniqueOptions.size !== options.length) {
      return {
        isValid: false,
        error: 'Options must be unique',
      }
    }
  }
  
  return { isValid: true }
}

/**
 * Validate workflow conditions
 */
export function validateWorkflowConditions(conditions: any): {
  isValid: boolean
  errors: string[]
} {
  const errors: string[] = []
  
  if (!Array.isArray(conditions)) {
    errors.push('Conditions must be an array of condition groups')
    return { isValid: false, errors }
  }
  
  const validOperators = ['equals', 'not_equals', 'greater_than', 'less_than', 'contains', 'not_contains', 'starts_with', 'ends_with', 'is_empty', 'is_not_empty']
  const validGroupOperators = ['AND', 'OR']
  
  for (let i = 0; i < conditions.length; i++) {
    const group = conditions[i]
    
    if (typeof group !== 'object' || !group) {
      errors.push(`Condition group ${i + 1} must be an object`)
      continue
    }
    
    if (!group.operator || !validGroupOperators.includes(group.operator)) {
      errors.push(`Condition group ${i + 1} must have a valid operator (AND/OR)`)
    }
    
    if (!Array.isArray(group.rules)) {
      errors.push(`Condition group ${i + 1} must have a rules array`)
      continue
    }
    
    for (let j = 0; j < group.rules.length; j++) {
      const rule = group.rules[j]
      
      if (typeof rule !== 'object' || !rule) {
        errors.push(`Rule ${j + 1} in group ${i + 1} must be an object`)
        continue
      }
      
      if (!rule.field) {
        errors.push(`Rule ${j + 1} in group ${i + 1} must have a field`)
      }
      
      if (!rule.operator || !validOperators.includes(rule.operator)) {
        errors.push(`Rule ${j + 1} in group ${i + 1} must have a valid operator`)
      }
      
      if (!['is_empty', 'is_not_empty'].includes(rule.operator) && rule.value === undefined) {
        errors.push(`Rule ${j + 1} in group ${i + 1} must have a value for operator ${rule.operator}`)
      }
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  }
}