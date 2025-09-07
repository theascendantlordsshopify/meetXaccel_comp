import { ReactNode } from 'react'

// Button types
export type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger'
export type ButtonSize = 'sm' | 'md' | 'lg'

export interface ButtonProps {
  variant?: ButtonVariant
  size?: ButtonSize
  disabled?: boolean
  loading?: boolean
  fullWidth?: boolean
  leftIcon?: ReactNode
  rightIcon?: ReactNode
  children: ReactNode
  onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void
  type?: 'button' | 'submit' | 'reset'
  className?: string
  'data-testid'?: string
}

// Input types
export type InputType = 'text' | 'email' | 'password' | 'number' | 'tel' | 'url' | 'search'
export type InputSize = 'sm' | 'md' | 'lg'

export interface InputProps {
  type?: InputType
  size?: InputSize
  label?: string
  placeholder?: string
  value?: string | number
  defaultValue?: string | number
  onChange?: (event: React.ChangeEvent<HTMLInputElement>) => void
  onBlur?: (event: React.FocusEvent<HTMLInputElement>) => void
  onFocus?: (event: React.FocusEvent<HTMLInputElement>) => void
  disabled?: boolean
  required?: boolean
  error?: string
  helpText?: string
  leftIcon?: ReactNode
  rightIcon?: ReactNode
  className?: string
  name?: string
  id?: string
  autoComplete?: string
  autoFocus?: boolean
  'data-testid'?: string
}

// Select types
export interface SelectProps {
  options: SelectOption[]
  value?: string | number | string[]
  defaultValue?: string | number | string[]
  onChange?: (value: string | number | string[]) => void
  placeholder?: string
  label?: string
  error?: string
  helpText?: string
  disabled?: boolean
  required?: boolean
  multiple?: boolean
  searchable?: boolean
  clearable?: boolean
  loading?: boolean
  className?: string
  name?: string
  id?: string
  'data-testid'?: string
}

export interface SelectOption {
  value: string | number
  label: string
  description?: string
  disabled?: boolean
  icon?: ReactNode
}

// Card types
export type CardVariant = 'default' | 'outlined' | 'elevated'

export interface CardProps {
  variant?: CardVariant
  padding?: boolean
  className?: string
  children: ReactNode
  onClick?: () => void
  hoverable?: boolean
  'data-testid'?: string
}

export interface CardHeaderProps {
  title?: string
  subtitle?: string
  action?: ReactNode
  className?: string
  children?: ReactNode
}

export interface CardContentProps {
  className?: string
  children: ReactNode
}

export interface CardFooterProps {
  className?: string
  children: ReactNode
}

// Modal types
export type ModalSize = 'sm' | 'md' | 'lg' | 'xl' | 'full'

export interface ModalProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  description?: string
  size?: ModalSize
  closeOnOverlayClick?: boolean
  closeOnEscape?: boolean
  showCloseButton?: boolean
  className?: string
  children: ReactNode
}

// Badge types
export type BadgeVariant = 'primary' | 'secondary' | 'success' | 'warning' | 'error' | 'info'
export type BadgeSize = 'sm' | 'md' | 'lg'

export interface BadgeProps {
  variant?: BadgeVariant
  size?: BadgeSize
  children: ReactNode
  className?: string
  'data-testid'?: string
}

// Toast types
export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface ToastProps {
  id: string
  type: ToastType
  title: string
  message?: string
  duration?: number
  action?: {
    label: string
    onClick: () => void
  }
  onDismiss: (id: string) => void
}

// Table types
export interface TableProps<T = any> {
  columns: TableColumn<T>[]
  data: T[]
  loading?: boolean
  error?: string
  emptyMessage?: string
  sortable?: boolean
  selectable?: boolean
  onSort?: (column: string, direction: SortDirection) => void
  onSelect?: (selectedRows: T[]) => void
  className?: string
  'data-testid'?: string
}

export interface TableColumn<T = any> {
  key: string
  label: string
  sortable?: boolean
  render?: (value: any, record: T, index: number) => ReactNode
  width?: string | number
  align?: 'left' | 'center' | 'right'
  className?: string
}

// Pagination types
export interface PaginationProps {
  currentPage: number
  totalPages: number
  pageSize: number
  totalItems: number
  onPageChange: (page: number) => void
  onPageSizeChange?: (pageSize: number) => void
  showPageSizeSelector?: boolean
  showInfo?: boolean
  className?: string
}

// Loading types
export interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg'
  color?: string
  className?: string
}

export interface LoadingOverlayProps {
  isLoading: boolean
  message?: string
  className?: string
  children: ReactNode
}

// Empty state types
export interface EmptyStateProps {
  icon?: ReactNode
  title: string
  description?: string
  action?: {
    label: string
    onClick: () => void
  }
  className?: string
}

// Form types
export interface FormGroupProps {
  label?: string
  error?: string
  helpText?: string
  required?: boolean
  className?: string
  children: ReactNode
}

export interface TextareaProps {
  label?: string
  placeholder?: string
  value?: string
  defaultValue?: string
  onChange?: (event: React.ChangeEvent<HTMLTextAreaElement>) => void
  onBlur?: (event: React.FocusEvent<HTMLTextAreaElement>) => void
  disabled?: boolean
  required?: boolean
  error?: string
  helpText?: string
  rows?: number
  maxLength?: number
  className?: string
  name?: string
  id?: string
  'data-testid'?: string
}

export interface CheckboxProps {
  label?: string
  description?: string
  checked?: boolean
  defaultChecked?: boolean
  onChange?: (checked: boolean) => void
  disabled?: boolean
  required?: boolean
  error?: string
  className?: string
  name?: string
  id?: string
  'data-testid'?: string
}

// Navigation types
export interface NavigationItem {
  name: string
  href: string
  icon?: string
  description?: string
  current?: boolean
  children?: NavigationItem[]
  badge?: string | number
}

export interface BreadcrumbProps {
  items: BreadcrumbItem[]
  className?: string
}

export interface BreadcrumbItem {
  label: string
  href?: string
  current?: boolean
}

// Layout types
export interface LayoutProps {
  children: ReactNode
  className?: string
}

export interface HeaderProps {
  title?: string
  subtitle?: string
  action?: ReactNode
  breadcrumbs?: BreadcrumbItem[]
  className?: string
}

export interface SidebarProps {
  navigation: NavigationItem[]
  collapsed?: boolean
  onToggle?: () => void
  className?: string
}

// Animation types
export type AnimationType = 'fade' | 'slide' | 'scale' | 'bounce'
export type AnimationDirection = 'up' | 'down' | 'left' | 'right'

export interface AnimationProps {
  type?: AnimationType
  direction?: AnimationDirection
  duration?: number
  delay?: number
  className?: string
  children: ReactNode
}

// Theme types
export interface ThemeConfig {
  colors: {
    primary: Record<string, string>
    secondary: Record<string, string>
    success: Record<string, string>
    warning: Record<string, string>
    error: Record<string, string>
  }
  spacing: Record<string, string>
  typography: {
    fontFamily: Record<string, string[]>
    fontSize: Record<string, [string, { lineHeight: string; letterSpacing?: string }]>
    fontWeight: Record<string, string>
  }
  borderRadius: Record<string, string>
  boxShadow: Record<string, string>
}

// Utility types for UI components
export type ComponentSize = 'sm' | 'md' | 'lg' | 'xl'
export type ComponentVariant = 'primary' | 'secondary' | 'success' | 'warning' | 'error' | 'info'
export type ComponentState = 'default' | 'hover' | 'active' | 'disabled' | 'loading'

// Import common types
import type { SortDirection, SelectOption, BreadcrumbItem } from './common'