import type { ApiError } from '@/types'

/**
 * Handle API errors consistently
 */
export function handleApiError(error: any): ApiError {
  // If it's already an ApiError, return as is
  if (error && typeof error.message === 'string' && typeof error.status === 'number') {
    return error as ApiError
  }

  // Handle Axios errors
  if (error.response) {
    return {
      message: error.response.data?.error || error.response.data?.message || 'An error occurred',
      status: error.response.status,
      details: error.response.data,
    }
  }

  // Handle network errors
  if (error.request) {
    return {
      message: 'Network error. Please check your connection.',
      status: 0,
    }
  }

  // Handle other errors
  return {
    message: error.message || 'An unexpected error occurred',
    status: 0,
  }
}

/**
 * Create query string from object
 */
export function createQueryString(params: Record<string, any>): string {
  const searchParams = new URLSearchParams()
  
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      if (Array.isArray(value)) {
        value.forEach(v => searchParams.append(key, String(v)))
      } else {
        searchParams.set(key, String(value))
      }
    }
  }
  
  return searchParams.toString()
}

/**
 * Parse query string to object
 */
export function parseQueryString(queryString: string): Record<string, any> {
  const params = new URLSearchParams(queryString)
  const result: Record<string, any> = {}
  
  for (const [key, value] of params.entries()) {
    if (result[key]) {
      // Handle multiple values for the same key
      if (Array.isArray(result[key])) {
        result[key].push(value)
      } else {
        result[key] = [result[key], value]
      }
    } else {
      result[key] = value
    }
  }
  
  return result
}

/**
 * Build API URL with query parameters
 */
export function buildApiUrl(endpoint: string, params?: Record<string, any>): string {
  const baseUrl = endpoint.startsWith('http') ? endpoint : `${import.meta.env.VITE_API_BASE_URL}${endpoint}`
  
  if (!params || Object.keys(params).length === 0) {
    return baseUrl
  }
  
  const queryString = createQueryString(params)
  const separator = baseUrl.includes('?') ? '&' : '?'
  
  return `${baseUrl}${separator}${queryString}`
}

/**
 * Transform request data (camelCase to snake_case)
 */
export function transformRequestData(data: any): any {
  if (data === null || data === undefined) {
    return data
  }
  
  if (Array.isArray(data)) {
    return data.map(transformRequestData)
  }
  
  if (data instanceof Date) {
    return data.toISOString()
  }
  
  if (typeof data === 'object') {
    const transformed: any = {}
    
    for (const [key, value] of Object.entries(data)) {
      const snakeKey = key.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`)
      transformed[snakeKey] = transformRequestData(value)
    }
    
    return transformed
  }
  
  return data
}

/**
 * Transform response data (snake_case to camelCase)
 */
export function transformResponseData(data: any): any {
  if (data === null || data === undefined) {
    return data
  }
  
  if (Array.isArray(data)) {
    return data.map(transformResponseData)
  }
  
  if (typeof data === 'object') {
    const transformed: any = {}
    
    for (const [key, value] of Object.entries(data)) {
      const camelKey = key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())
      transformed[camelKey] = transformResponseData(value)
    }
    
    return transformed
  }
  
  return data
}

/**
 * Create form data for file uploads
 */
export function createFormData(data: Record<string, any>): FormData {
  const formData = new FormData()
  
  for (const [key, value] of Object.entries(data)) {
    if (value instanceof File) {
      formData.append(key, value)
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (item instanceof File) {
          formData.append(`${key}[${index}]`, item)
        } else {
          formData.append(`${key}[${index}]`, String(item))
        }
      })
    } else if (value !== undefined && value !== null) {
      formData.append(key, String(value))
    }
  }
  
  return formData
}

/**
 * Retry API call with exponential backoff
 */
export async function retryApiCall<T>(
  apiCall: () => Promise<T>,
  maxRetries: number = 3,
  baseDelay: number = 1000
): Promise<T> {
  let lastError: Error
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await apiCall()
    } catch (error) {
      lastError = error as Error
      
      // Don't retry on client errors (4xx)
      if (error && typeof error === 'object' && 'status' in error) {
        const status = (error as any).status
        if (status >= 400 && status < 500) {
          throw error
        }
      }
      
      if (attempt === maxRetries) {
        throw lastError
      }
      
      // Exponential backoff with jitter
      const delay = baseDelay * Math.pow(2, attempt - 1) + Math.random() * 1000
      await new Promise(resolve => setTimeout(resolve, delay))
    }
  }
  
  throw lastError!
}

/**
 * Check if response is paginated
 */
export function isPaginatedResponse(response: any): boolean {
  return (
    response &&
    typeof response === 'object' &&
    'results' in response &&
    'count' in response &&
    Array.isArray(response.results)
  )
}

/**
 * Extract pagination info from response
 */
export function extractPaginationInfo(response: any): {
  page: number
  pageSize: number
  total: number
  totalPages: number
  hasNext: boolean
  hasPrevious: boolean
} {
  if (!isPaginatedResponse(response)) {
    return {
      page: 1,
      pageSize: 0,
      total: 0,
      totalPages: 1,
      hasNext: false,
      hasPrevious: false,
    }
  }
  
  const { count, next, previous, results } = response
  const pageSize = results.length
  const totalPages = Math.ceil(count / pageSize)
  
  // Extract page number from next/previous URLs
  let page = 1
  if (next) {
    const nextUrl = new URL(next)
    const nextPage = nextUrl.searchParams.get('page')
    page = nextPage ? parseInt(nextPage) - 1 : 1
  } else if (previous) {
    const prevUrl = new URL(previous)
    const prevPage = prevUrl.searchParams.get('page')
    page = prevPage ? parseInt(prevPage) + 1 : totalPages
  }
  
  return {
    page,
    pageSize,
    total: count,
    totalPages,
    hasNext: !!next,
    hasPrevious: !!previous,
  }
}

/**
 * Create cache key for API requests
 */
export function createCacheKey(endpoint: string, params?: Record<string, any>): string {
  const baseKey = endpoint.replace(/[^a-zA-Z0-9]/g, '_')
  
  if (!params || Object.keys(params).length === 0) {
    return baseKey
  }
  
  const sortedParams = Object.keys(params)
    .sort()
    .map(key => `${key}:${params[key]}`)
    .join('|')
  
  return `${baseKey}_${btoa(sortedParams)}`
}

/**
 * Check if API call should be retried
 */
export function shouldRetryApiCall(error: any, attempt: number, maxRetries: number): boolean {
  // Don't retry if we've reached max attempts
  if (attempt >= maxRetries) return false
  
  // Don't retry client errors (4xx)
  if (error?.status >= 400 && error?.status < 500) return false
  
  // Retry server errors (5xx) and network errors
  return error?.status >= 500 || error?.status === 0
}

/**
 * Calculate retry delay with exponential backoff
 */
export function calculateRetryDelay(attempt: number, baseDelay: number = 1000): number {
  return baseDelay * Math.pow(2, attempt - 1) + Math.random() * 1000
}