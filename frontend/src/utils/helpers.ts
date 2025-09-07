/**
 * Debounce function to limit the rate of function calls
 */
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null
  
  return (...args: Parameters<T>) => {
    if (timeout) {
      clearTimeout(timeout)
    }
    
    timeout = setTimeout(() => {
      func(...args)
    }, wait)
  }
}

/**
 * Throttle function to limit the rate of function calls
 */
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean = false
  
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args)
      inThrottle = true
      setTimeout(() => (inThrottle = false), limit)
    }
  }
}

/**
 * Deep clone an object
 */
export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj
  }
  
  if (obj instanceof Date) {
    return new Date(obj.getTime()) as T
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => deepClone(item)) as T
  }
  
  const cloned = {} as T
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      cloned[key] = deepClone(obj[key])
    }
  }
  
  return cloned
}

/**
 * Check if two objects are deeply equal
 */
export function deepEqual(a: any, b: any): boolean {
  if (a === b) return true
  
  if (a instanceof Date && b instanceof Date) {
    return a.getTime() === b.getTime()
  }
  
  if (!a || !b || (typeof a !== 'object' && typeof b !== 'object')) {
    return a === b
  }
  
  if (a === null || a === undefined || b === null || b === undefined) {
    return false
  }
  
  if (a.prototype !== b.prototype) return false
  
  const keys = Object.keys(a)
  if (keys.length !== Object.keys(b).length) {
    return false
  }
  
  return keys.every(k => deepEqual(a[k], b[k]))
}

/**
 * Generate a random ID
 */
export function generateId(prefix?: string): string {
  const id = Math.random().toString(36).substr(2, 9)
  return prefix ? `${prefix}-${id}` : id
}

/**
 * Capitalize first letter of a string
 */
export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1)
}

/**
 * Convert string to title case
 */
export function toTitleCase(str: string): string {
  return str.replace(/\w\S*/g, (txt) => 
    txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
  )
}

/**
 * Convert camelCase to snake_case
 */
export function camelToSnake(str: string): string {
  return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`)
}

/**
 * Convert snake_case to camelCase
 */
export function snakeToCamel(str: string): string {
  return str.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())
}

/**
 * Convert object keys from camelCase to snake_case
 */
export function objectToSnakeCase(obj: Record<string, any>): Record<string, any> {
  const result: Record<string, any> = {}
  
  for (const [key, value] of Object.entries(obj)) {
    const snakeKey = camelToSnake(key)
    
    if (value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Date)) {
      result[snakeKey] = objectToSnakeCase(value)
    } else if (Array.isArray(value)) {
      result[snakeKey] = value.map(item => 
        item && typeof item === 'object' && !(item instanceof Date) 
          ? objectToSnakeCase(item) 
          : item
      )
    } else {
      result[snakeKey] = value
    }
  }
  
  return result
}

/**
 * Convert object keys from snake_case to camelCase
 */
export function objectToCamelCase(obj: Record<string, any>): Record<string, any> {
  const result: Record<string, any> = {}
  
  for (const [key, value] of Object.entries(obj)) {
    const camelKey = snakeToCamel(key)
    
    if (value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Date)) {
      result[camelKey] = objectToCamelCase(value)
    } else if (Array.isArray(value)) {
      result[camelKey] = value.map(item => 
        item && typeof item === 'object' && !(item instanceof Date) 
          ? objectToCamelCase(item) 
          : item
      )
    } else {
      result[camelKey] = value
    }
  }
  
  return result
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text: string, length: number): string {
  if (text.length <= length) return text
  return text.slice(0, length) + '...'
}

/**
 * Format file size
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

/**
 * Format number with commas
 */
export function formatNumber(num: number): string {
  return num.toLocaleString()
}

/**
 * Format percentage
 */
export function formatPercentage(value: number, decimals: number = 1): string {
  return `${value.toFixed(decimals)}%`
}

/**
 * Get initials from a name
 */
export function getInitials(name: string): string {
  return name
    .split(' ')
    .map(word => word.charAt(0))
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

/**
 * Generate a color from a string (for avatars, badges, etc.)
 */
export function stringToColor(str: string): string {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash)
  }
  
  const hue = hash % 360
  return `hsl(${hue}, 70%, 50%)`
}

/**
 * Sleep function for delays
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Retry function with exponential backoff
 */
export async function retry<T>(
  fn: () => Promise<T>,
  maxAttempts: number = 3,
  baseDelay: number = 1000
): Promise<T> {
  let lastError: Error
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error as Error
      
      if (attempt === maxAttempts) {
        throw lastError
      }
      
      const delay = baseDelay * Math.pow(2, attempt - 1)
      await sleep(delay)
    }
  }
  
  throw lastError!
}

/**
 * Create a download link for data
 */
export function downloadData(data: string, filename: string, type: string = 'text/plain'): void {
  const blob = new Blob([data], { type })
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  
  document.body.removeChild(link)
  window.URL.revokeObjectURL(url)
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return true
    } else {
      // Fallback for older browsers
      const textArea = document.createElement('textarea')
      textArea.value = text
      textArea.style.position = 'fixed'
      textArea.style.left = '-999999px'
      textArea.style.top = '-999999px'
      document.body.appendChild(textArea)
      textArea.focus()
      textArea.select()
      
      const success = document.execCommand('copy')
      document.body.removeChild(textArea)
      return success
    }
  } catch {
    return false
  }
}

/**
 * Get nested object property safely
 */
export function getNestedProperty(obj: any, path: string): any {
  return path.split('.').reduce((current, key) => current?.[key], obj)
}

/**
 * Set nested object property safely
 */
export function setNestedProperty(obj: any, path: string, value: any): void {
  const keys = path.split('.')
  const lastKey = keys.pop()!
  const target = keys.reduce((current, key) => {
    if (!(key in current)) {
      current[key] = {}
    }
    return current[key]
  }, obj)
  
  target[lastKey] = value
}

/**
 * Remove undefined values from an object
 */
export function removeUndefined<T extends Record<string, any>>(obj: T): Partial<T> {
  const result: Partial<T> = {}
  
  for (const [key, value] of Object.entries(obj)) {
    if (value !== undefined) {
      result[key as keyof T] = value
    }
  }
  
  return result
}

/**
 * Group array items by a key
 */
export function groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
  return array.reduce((groups, item) => {
    const group = String(item[key])
    groups[group] = groups[group] || []
    groups[group].push(item)
    return groups
  }, {} as Record<string, T[]>)
}

/**
 * Sort array by multiple keys
 */
export function sortBy<T>(
  array: T[],
  ...keys: Array<keyof T | ((item: T) => any)>
): T[] {
  return array.sort((a, b) => {
    for (const key of keys) {
      const aVal = typeof key === 'function' ? key(a) : a[key]
      const bVal = typeof key === 'function' ? key(b) : b[key]
      
      if (aVal < bVal) return -1
      if (aVal > bVal) return 1
    }
    return 0
  })
}

/**
 * Create a URL with query parameters
 */
export function createUrl(base: string, params: Record<string, any>): string {
  const url = new URL(base, window.location.origin)
  
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, String(value))
    }
  }
  
  return url.toString()
}

/**
 * Parse query parameters from URL
 */
export function parseQueryParams(search: string): Record<string, string> {
  const params = new URLSearchParams(search)
  const result: Record<string, string> = {}
  
  for (const [key, value] of params.entries()) {
    result[key] = value
  }
  
  return result
}

/**
 * Check if user has permission
 */
export function hasPermission(user: any, permission: string): boolean {
  if (!user?.roles) return false
  
  return user.roles.some((role: any) =>
    role.role_permissions?.some((perm: any) => perm.codename === permission)
  )
}

/**
 * Check if user has role
 */
export function hasRole(user: any, roleName: string): boolean {
  if (!user?.roles) return false
  
  return user.roles.some((role: any) => role.name === roleName)
}

/**
 * Format error message from API response
 */
export function formatApiError(error: any): string {
  if (typeof error === 'string') return error
  
  if (error?.message) return error.message
  
  if (error?.errors) {
    const firstError = Object.values(error.errors)[0]
    if (Array.isArray(firstError)) {
      return firstError[0]
    }
    return String(firstError)
  }
  
  if (error?.detail) return error.detail
  if (error?.error) return error.error
  
  return 'An unexpected error occurred'
}

/**
 * Create a stable key for React components
 */
export function createKey(...parts: (string | number | undefined)[]): string {
  return parts.filter(Boolean).join('-')
}

/**
 * Check if code is running in browser
 */
export function isBrowser(): boolean {
  return typeof window !== 'undefined'
}

/**
 * Check if device is mobile
 */
export function isMobile(): boolean {
  if (!isBrowser()) return false
  return window.innerWidth < 768
}

/**
 * Check if device is tablet
 */
export function isTablet(): boolean {
  if (!isBrowser()) return false
  return window.innerWidth >= 768 && window.innerWidth < 1024
}

/**
 * Check if device is desktop
 */
export function isDesktop(): boolean {
  if (!isBrowser()) return false
  return window.innerWidth >= 1024
}

/**
 * Get device type
 */
export function getDeviceType(): 'mobile' | 'tablet' | 'desktop' {
  if (isMobile()) return 'mobile'
  if (isTablet()) return 'tablet'
  return 'desktop'
}

/**
 * Scroll to element
 */
export function scrollToElement(elementId: string, offset: number = 0): void {
  const element = document.getElementById(elementId)
  if (element) {
    const top = element.offsetTop - offset
    window.scrollTo({ top, behavior: 'smooth' })
  }
}

/**
 * Focus element
 */
export function focusElement(elementId: string): void {
  const element = document.getElementById(elementId)
  if (element) {
    element.focus()
  }
}

/**
 * Local storage helpers
 */
export const localStorage = {
  get: <T>(key: string, defaultValue?: T): T | null => {
    if (!isBrowser()) return defaultValue || null
    
    try {
      const item = window.localStorage.getItem(key)
      return item ? JSON.parse(item) : defaultValue || null
    } catch {
      return defaultValue || null
    }
  },
  
  set: (key: string, value: any): void => {
    if (!isBrowser()) return
    
    try {
      window.localStorage.setItem(key, JSON.stringify(value))
    } catch {
      // Ignore storage errors
    }
  },
  
  remove: (key: string): void => {
    if (!isBrowser()) return
    
    try {
      window.localStorage.removeItem(key)
    } catch {
      // Ignore storage errors
    }
  },
  
  clear: (): void => {
    if (!isBrowser()) return
    
    try {
      window.localStorage.clear()
    } catch {
      // Ignore storage errors
    }
  },
}

/**
 * Session storage helpers
 */
export const sessionStorage = {
  get: <T>(key: string, defaultValue?: T): T | null => {
    if (!isBrowser()) return defaultValue || null
    
    try {
      const item = window.sessionStorage.getItem(key)
      return item ? JSON.parse(item) : defaultValue || null
    } catch {
      return defaultValue || null
    }
  },
  
  set: (key: string, value: any): void => {
    if (!isBrowser()) return
    
    try {
      window.sessionStorage.setItem(key, JSON.stringify(value))
    } catch {
      // Ignore storage errors
    }
  },
  
  remove: (key: string): void => {
    if (!isBrowser()) return
    
    try {
      window.sessionStorage.removeItem(key)
    } catch {
      // Ignore storage errors
    }
  },
  
  clear: (): void => {
    if (!isBrowser()) return
    
    try {
      window.sessionStorage.clear()
    } catch {
      // Ignore storage errors
    }
  },
}

/**
 * Array utilities
 */
export const arrayUtils = {
  unique: <T>(array: T[]): T[] => [...new Set(array)],
  
  chunk: <T>(array: T[], size: number): T[][] => {
    const chunks: T[][] = []
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size))
    }
    return chunks
  },
  
  shuffle: <T>(array: T[]): T[] => {
    const shuffled = [...array]
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1))
      ;[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]]
    }
    return shuffled
  },
  
  move: <T>(array: T[], fromIndex: number, toIndex: number): T[] => {
    const result = [...array]
    const [removed] = result.splice(fromIndex, 1)
    result.splice(toIndex, 0, removed)
    return result
  },
}

/**
 * URL utilities
 */
export const urlUtils = {
  isExternal: (url: string): boolean => {
    try {
      const urlObj = new URL(url)
      return urlObj.origin !== window.location.origin
    } catch {
      return false
    }
  },
  
  addParams: (url: string, params: Record<string, any>): string => {
    const urlObj = new URL(url, window.location.origin)
    
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== '') {
        urlObj.searchParams.set(key, String(value))
      }
    }
    
    return urlObj.toString()
  },
  
  removeParams: (url: string, ...params: string[]): string => {
    const urlObj = new URL(url, window.location.origin)
    
    for (const param of params) {
      urlObj.searchParams.delete(param)
    }
    
    return urlObj.toString()
  },
}