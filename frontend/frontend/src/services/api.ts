import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import { API_BASE_URL } from '@/constants'
import { authStore } from '@/stores/authStore'
import { uiStore } from '@/stores/uiStore'
import type { ApiResponse, ApiError } from '@/types'

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = authStore.getState().token
    if (token) {
      config.headers.Authorization = `Token ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response: AxiosResponse) => {
    return response
  },
  (error) => {
    const { response } = error

    // Handle network errors
    if (!response) {
      uiStore.getState().addNotification({
        id: Date.now().toString(),
        type: 'error',
        title: 'Network Error',
        message: 'Please check your internet connection and try again.',
      })
      return Promise.reject({
        message: 'Network error',
        status: 0,
      } as ApiError)
    }

    const { status, data } = response

    // Handle authentication errors
    if (status === 401) {
      authStore.getState().logout()
      window.location.href = '/login'
      return Promise.reject({
        message: 'Authentication required',
        status: 401,
      } as ApiError)
    }

    // Handle authorization errors
    if (status === 403) {
      uiStore.getState().addNotification({
        id: Date.now().toString(),
        type: 'error',
        title: 'Access Denied',
        message: 'You do not have permission to perform this action.',
      })
      return Promise.reject({
        message: 'Access denied',
        status: 403,
      } as ApiError)
    }

    // Handle rate limiting
    if (status === 429) {
      uiStore.getState().addNotification({
        id: Date.now().toString(),
        type: 'warning',
        title: 'Rate Limited',
        message: 'Too many requests. Please try again in a moment.',
      })
      return Promise.reject({
        message: 'Rate limited',
        status: 429,
      } as ApiError)
    }

    // Handle validation errors
    if (status === 400) {
      const errorMessage = data?.error || data?.message || 'Validation error'
      return Promise.reject({
        message: errorMessage,
        status: 400,
        details: data?.errors || data?.details,
      } as ApiError)
    }

    // Handle not found errors
    if (status === 404) {
      return Promise.reject({
        message: 'Resource not found',
        status: 404,
      } as ApiError)
    }

    // Handle server errors
    if (status >= 500) {
      uiStore.getState().addNotification({
        id: Date.now().toString(),
        type: 'error',
        title: 'Server Error',
        message: 'An unexpected error occurred. Please try again later.',
      })
      return Promise.reject({
        message: 'Server error',
        status: status,
      } as ApiError)
    }

    // Handle other errors
    const errorMessage = data?.error || data?.message || 'An error occurred'
    return Promise.reject({
      message: errorMessage,
      status: status,
      details: data,
    } as ApiError)
  }
)

// Generic API methods
export const apiClient = {
  get: <T = any>(url: string, config?: AxiosRequestConfig): Promise<T> =>
    api.get(url, config).then((response) => response.data),

  post: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> =>
    api.post(url, data, config).then((response) => response.data),

  put: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> =>
    api.put(url, data, config).then((response) => response.data),

  patch: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> =>
    api.patch(url, data, config).then((response) => response.data),

  delete: <T = any>(url: string, config?: AxiosRequestConfig): Promise<T> =>
    api.delete(url, config).then((response) => response.data),

  upload: <T = any>(url: string, file: File, onProgress?: (progress: number) => void): Promise<T> => {
    const formData = new FormData()
    formData.append('file', file)

    return api.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      },
    }).then((response) => response.data)
  },
}

// Utility functions for API calls
export const handleApiError = (error: any): ApiError => {
  if (error.response) {
    return {
      message: error.response.data?.error || error.response.data?.message || 'An error occurred',
      status: error.response.status,
      details: error.response.data,
    }
  } else if (error.request) {
    return {
      message: 'Network error. Please check your connection.',
      status: 0,
    }
  } else {
    return {
      message: error.message || 'An unexpected error occurred',
      status: 0,
    }
  }
}

export const createApiResponse = <T>(data: T, message?: string): ApiResponse<T> => ({
  data,
  message,
})

export const isApiError = (error: any): error is ApiError => {
  return error && typeof error.message === 'string' && typeof error.status === 'number'
}

// Request/Response transformers
export const transformRequest = (data: any): any => {
  // Transform camelCase to snake_case for API
  if (typeof data === 'object' && data !== null) {
    const transformed: any = {}
    for (const [key, value] of Object.entries(data)) {
      const snakeKey = key.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)
      transformed[snakeKey] = value
    }
    return transformed
  }
  return data
}

export const transformResponse = (data: any): any => {
  // Transform snake_case to camelCase from API
  if (typeof data === 'object' && data !== null) {
    if (Array.isArray(data)) {
      return data.map(transformResponse)
    }
    
    const transformed: any = {}
    for (const [key, value] of Object.entries(data)) {
      const camelKey = key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())
      transformed[camelKey] = typeof value === 'object' ? transformResponse(value) : value
    }
    return transformed
  }
  return data
}

// Add request/response transformers to axios instance
api.defaults.transformRequest = [
  (data, headers) => {
    if (headers['Content-Type'] === 'application/json') {
      return JSON.stringify(transformRequest(data))
    }
    return data
  },
  ...axios.defaults.transformRequest!,
]

api.defaults.transformResponse = [
  ...axios.defaults.transformResponse!,
  (data) => {
    try {
      return transformResponse(JSON.parse(data))
    } catch {
      return data
    }
  },
]

export default api