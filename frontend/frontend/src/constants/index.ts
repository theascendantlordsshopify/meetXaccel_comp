// API Configuration
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'
export const PUBLIC_API_BASE_URL = import.meta.env.VITE_PUBLIC_API_BASE_URL || 'http://localhost:8000'

// App Configuration
export const APP_NAME = import.meta.env.VITE_APP_NAME || 'Calendly Clone'
export const APP_VERSION = import.meta.env.VITE_APP_VERSION || '1.0.0'
export const APP_DESCRIPTION = import.meta.env.VITE_APP_DESCRIPTION || 'Professional scheduling platform'

// Feature Flags
export const ENABLE_ANALYTICS = import.meta.env.VITE_ENABLE_ANALYTICS === 'true'
export const ENABLE_DEBUG = import.meta.env.VITE_ENABLE_DEBUG === 'true'
export const ENABLE_MOCK_DATA = import.meta.env.VITE_ENABLE_MOCK_DATA === 'true'

// Cache Settings
export const CACHE_DURATION = parseInt(import.meta.env.VITE_CACHE_DURATION || '300000')
export const STALE_TIME = parseInt(import.meta.env.VITE_STALE_TIME || '60000')

// UI Settings
export const DEFAULT_THEME = import.meta.env.VITE_DEFAULT_THEME || 'light'
export const ENABLE_ANIMATIONS = import.meta.env.VITE_ENABLE_ANIMATIONS !== 'false'
export const SIDEBAR_DEFAULT_COLLAPSED = import.meta.env.VITE_SIDEBAR_DEFAULT_COLLAPSED === 'true'

// Pagination
export const DEFAULT_PAGE_SIZE = 20
export const PAGE_SIZE_OPTIONS = [10, 20, 50, 100]

// Date & Time
export const DEFAULT_DATE_FORMAT = 'MMM dd, yyyy'
export const DEFAULT_TIME_FORMAT = 'h:mm a'
export const DEFAULT_DATETIME_FORMAT = 'MMM dd, yyyy h:mm a'

// Validation
export const MIN_PASSWORD_LENGTH = 8
export const MAX_FILE_SIZE = 5 * 1024 * 1024 // 5MB
export const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']

// Booking
export const MIN_BOOKING_NOTICE_MINUTES = 15
export const MAX_BOOKING_ADVANCE_DAYS = 365
export const DEFAULT_BUFFER_TIME_MINUTES = 0
export const SLOT_INTERVAL_MINUTES = 15

// Notifications
export const TOAST_DURATION = 5000
export const MAX_NOTIFICATIONS = 5

// Routes
export const ROUTES = {
  HOME: '/',
  LOGIN: '/login',
  REGISTER: '/register',
  DASHBOARD: '/dashboard',
  EVENTS: '/dashboard/events',
  BOOKINGS: '/dashboard/bookings',
  AVAILABILITY: '/dashboard/availability',
  INTEGRATIONS: '/dashboard/integrations',
  WORKFLOWS: '/dashboard/workflows',
  NOTIFICATIONS: '/dashboard/notifications',
  CONTACTS: '/dashboard/contacts',
  SETTINGS: '/dashboard/settings',
  PROFILE: '/dashboard/profile',
  // Public routes
  PUBLIC_ORGANIZER: '/:organizerSlug',
  PUBLIC_BOOKING: '/:organizerSlug/:eventTypeSlug',
  BOOKING_MANAGEMENT: '/booking/:accessToken/manage',
} as const

// Status Colors
export const STATUS_COLORS = {
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
} as const

// Event Type Durations (in minutes)
export const EVENT_DURATIONS = [15, 30, 45, 60, 90, 120, 180, 240]

// Location Types
export const LOCATION_TYPES = [
  { value: 'video_call', label: 'Video Call' },
  { value: 'phone_call', label: 'Phone Call' },
  { value: 'in_person', label: 'In Person' },
  { value: 'custom', label: 'Custom' },
]

// Recurrence Types
export const RECURRENCE_TYPES = [
  { value: 'none', label: 'No Recurrence' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
]

// Question Types
export const QUESTION_TYPES = [
  { value: 'text', label: 'Text Input' },
  { value: 'textarea', label: 'Long Text' },
  { value: 'select', label: 'Single Select' },
  { value: 'multiselect', label: 'Multiple Select' },
  { value: 'checkbox', label: 'Checkbox' },
  { value: 'radio', label: 'Radio Buttons' },
  { value: 'email', label: 'Email' },
  { value: 'phone', label: 'Phone Number' },
  { value: 'number', label: 'Number' },
  { value: 'date', label: 'Date' },
  { value: 'time', label: 'Time' },
  { value: 'url', label: 'URL' },
]

// Workflow Triggers
export const WORKFLOW_TRIGGERS = [
  { value: 'booking_created', label: 'Booking Created' },
  { value: 'booking_cancelled', label: 'Booking Cancelled' },
  { value: 'booking_completed', label: 'Booking Completed' },
  { value: 'before_meeting', label: 'Before Meeting' },
  { value: 'after_meeting', label: 'After Meeting' },
]

// Workflow Action Types
export const WORKFLOW_ACTION_TYPES = [
  { value: 'send_email', label: 'Send Email' },
  { value: 'send_sms', label: 'Send SMS' },
  { value: 'webhook', label: 'Trigger Webhook' },
  { value: 'update_booking', label: 'Update Booking' },
]

// Notification Types
export const NOTIFICATION_TYPES = [
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'SMS' },
]

// Integration Providers
export const CALENDAR_PROVIDERS = [
  { value: 'google', label: 'Google Calendar' },
  { value: 'outlook', label: 'Microsoft Outlook' },
  { value: 'apple', label: 'Apple Calendar' },
]

export const VIDEO_PROVIDERS = [
  { value: 'zoom', label: 'Zoom' },
  { value: 'google_meet', label: 'Google Meet' },
  { value: 'microsoft_teams', label: 'Microsoft Teams' },
  { value: 'webex', label: 'Cisco Webex' },
]

// Time Zones (Common ones - full list would be loaded from API)
export const COMMON_TIMEZONES = [
  { value: 'UTC', label: 'UTC' },
  { value: 'America/New_York', label: 'Eastern Time (US & Canada)' },
  { value: 'America/Chicago', label: 'Central Time (US & Canada)' },
  { value: 'America/Denver', label: 'Mountain Time (US & Canada)' },
  { value: 'America/Los_Angeles', label: 'Pacific Time (US & Canada)' },
  { value: 'Europe/London', label: 'London' },
  { value: 'Europe/Paris', label: 'Paris' },
  { value: 'Europe/Berlin', label: 'Berlin' },
  { value: 'Asia/Tokyo', label: 'Tokyo' },
  { value: 'Asia/Shanghai', label: 'Shanghai' },
  { value: 'Asia/Kolkata', label: 'Mumbai' },
  { value: 'Australia/Sydney', label: 'Sydney' },
]

// Error Messages
export const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Network error. Please check your connection.',
  UNAUTHORIZED: 'You are not authorized to perform this action.',
  FORBIDDEN: 'Access denied.',
  NOT_FOUND: 'The requested resource was not found.',
  VALIDATION_ERROR: 'Please check your input and try again.',
  SERVER_ERROR: 'An unexpected error occurred. Please try again later.',
  BOOKING_CONFLICT: 'This time slot is no longer available.',
  INVALID_TOKEN: 'Invalid or expired token.',
  RATE_LIMIT: 'Too many requests. Please try again later.',
} as const

// Success Messages
export const SUCCESS_MESSAGES = {
  BOOKING_CREATED: 'Booking created successfully!',
  BOOKING_CANCELLED: 'Booking cancelled successfully.',
  BOOKING_UPDATED: 'Booking updated successfully.',
  PROFILE_UPDATED: 'Profile updated successfully.',
  SETTINGS_SAVED: 'Settings saved successfully.',
  EMAIL_SENT: 'Email sent successfully.',
  INTEGRATION_CONNECTED: 'Integration connected successfully.',
  WORKFLOW_CREATED: 'Workflow created successfully.',
} as const