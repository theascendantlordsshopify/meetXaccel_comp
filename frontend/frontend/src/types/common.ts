// Common utility types
export type Status = 'idle' | 'loading' | 'success' | 'error'

export type Theme = 'light' | 'dark' | 'system'

export type SortDirection = 'asc' | 'desc'

export interface SortConfig {
  key: string
  direction: SortDirection
}

export interface FilterConfig {
  [key: string]: any
}

export interface PaginationConfig {
  page: number
  pageSize: number
  total: number
}

export interface TableColumn<T = any> {
  key: string
  label: string
  sortable?: boolean
  render?: (value: any, record: T) => React.ReactNode
  width?: string | number
  align?: 'left' | 'center' | 'right'
}

export interface SelectOption {
  value: string | number
  label: string
  description?: string
  disabled?: boolean
  icon?: React.ComponentType<any>
}

export interface TabItem {
  id: string
  label: string
  content: React.ReactNode
  disabled?: boolean
  badge?: string | number
}

export interface BreadcrumbItem {
  label: string
  href?: string
  current?: boolean
}

export interface MenuItem {
  id: string
  label: string
  href?: string
  icon?: React.ComponentType<any>
  onClick?: () => void
  disabled?: boolean
  children?: MenuItem[]
}

export interface NotificationItem {
  id: string
  type: 'success' | 'error' | 'warning' | 'info'
  title: string
  message?: string
  duration?: number
  action?: {
    label: string
    onClick: () => void
  }
}

export interface ModalProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  description?: string
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full'
  children: React.ReactNode
}

export interface ConfirmDialogProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
  title: string
  message: string
  confirmText?: string
  cancelText?: string
  variant?: 'danger' | 'warning' | 'info'
}

// Form types
export interface FormField {
  name: string
  label: string
  type: string
  required?: boolean
  placeholder?: string
  helpText?: string
  options?: SelectOption[]
  validation?: any
}

export interface FormSection {
  title: string
  description?: string
  fields: FormField[]
}

// Date & Time types
export interface TimeSlot {
  start: string
  end: string
  available: boolean
  reason?: string
}

export interface DateRange {
  start: Date
  end: Date
}

export interface TimeRange {
  start: string
  end: string
}

// File upload types
export interface FileUpload {
  file: File
  progress: number
  status: 'pending' | 'uploading' | 'success' | 'error'
  error?: string
  url?: string
}

// Search types
export interface SearchResult<T = any> {
  items: T[]
  total: number
  query: string
  filters?: FilterConfig
}

// Chart data types
export interface ChartDataPoint {
  label: string
  value: number
  color?: string
}

export interface TimeSeriesDataPoint {
  date: string
  value: number
  label?: string
}

// Error types
export interface ValidationError {
  field: string
  message: string
}

export interface ApiErrorResponse {
  error: string
  details?: any
  errors?: Record<string, string[]>
  status: number
}

// Loading states
export interface LoadingState {
  isLoading: boolean
  error?: string | null
  lastUpdated?: Date
}

// Feature flags
export interface FeatureFlags {
  enableAnalytics: boolean
  enableDebug: boolean
  enableMockData: boolean
  enablePushNotifications: boolean
  enableRealTimeUpdates: boolean
  enableAnimations: boolean
}

// Environment config
export interface AppConfig {
  apiBaseUrl: string
  publicApiBaseUrl: string
  appName: string
  appVersion: string
  appDescription: string
  nodeEnv: string
  featureFlags: FeatureFlags
  cacheDuration: number
  staleTime: number
  defaultTheme: Theme
  sidebarDefaultCollapsed: boolean
}

// Generic utility types
export type Nullable<T> = T | null
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>
export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P]
}

// Event handler types
export type EventHandler<T = any> = (event: T) => void
export type AsyncEventHandler<T = any> = (event: T) => Promise<void>
export type ChangeHandler<T = any> = (value: T) => void
export type SubmitHandler<T = any> = (data: T) => void | Promise<void>

// Component prop types
export interface BaseComponentProps {
  className?: string
  children?: React.ReactNode
  id?: string
  'data-testid'?: string
}

export interface InteractiveComponentProps extends BaseComponentProps {
  disabled?: boolean
  loading?: boolean
  onClick?: EventHandler<React.MouseEvent>
}

export interface FormComponentProps extends BaseComponentProps {
  name?: string
  value?: any
  onChange?: ChangeHandler<any>
  onBlur?: EventHandler<React.FocusEvent>
  error?: string
  required?: boolean
  disabled?: boolean
  placeholder?: string
  helpText?: string
}