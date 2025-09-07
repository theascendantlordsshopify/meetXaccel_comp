import { z } from 'zod'

// Authentication Forms
export const loginSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
  remember_me: z.boolean().optional(),
})

export const registerSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  first_name: z.string().min(1, 'First name is required'),
  last_name: z.string().min(1, 'Last name is required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  password_confirm: z.string(),
  terms_accepted: z.boolean().refine(val => val === true, {
    message: 'You must accept the terms and conditions',
  }),
}).refine(data => data.password === data.password_confirm, {
  message: 'Passwords do not match',
  path: ['password_confirm'],
})

export const changePasswordSchema = z.object({
  old_password: z.string().min(1, 'Current password is required'),
  new_password: z.string().min(8, 'Password must be at least 8 characters'),
  new_password_confirm: z.string(),
}).refine(data => data.new_password === data.new_password_confirm, {
  message: 'Passwords do not match',
  path: ['new_password_confirm'],
})

export const passwordResetRequestSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
})

export const passwordResetConfirmSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  new_password: z.string().min(8, 'Password must be at least 8 characters'),
  new_password_confirm: z.string(),
}).refine(data => data.new_password === data.new_password_confirm, {
  message: 'Passwords do not match',
  path: ['new_password_confirm'],
})

// Event Type Forms
export const eventTypeSchema = z.object({
  name: z.string().min(1, 'Event name is required').max(200, 'Name is too long'),
  description: z.string().optional(),
  duration: z.number().min(15, 'Minimum duration is 15 minutes').max(480, 'Maximum duration is 8 hours'),
  max_attendees: z.number().min(1, 'At least 1 attendee required').max(100, 'Maximum 100 attendees'),
  enable_waitlist: z.boolean().optional(),
  is_active: z.boolean().optional(),
  is_private: z.boolean().optional(),
  min_scheduling_notice: z.number().min(0, 'Cannot be negative').max(10080, 'Maximum 1 week'),
  max_scheduling_horizon: z.number().min(60, 'Minimum 1 hour').max(525600, 'Maximum 1 year'),
  buffer_time_before: z.number().min(0, 'Cannot be negative').max(120, 'Maximum 2 hours'),
  buffer_time_after: z.number().min(0, 'Cannot be negative').max(120, 'Maximum 2 hours'),
  max_bookings_per_day: z.number().min(1, 'At least 1 booking').max(50, 'Maximum 50 bookings').optional(),
  slot_interval_minutes: z.number().min(0, 'Cannot be negative').max(60, 'Maximum 1 hour').optional(),
  location_type: z.enum(['video_call', 'phone_call', 'in_person', 'custom']),
  location_details: z.string().optional(),
  redirect_url_after_booking: z.string().url('Must be a valid URL').optional().or(z.literal('')),
})

export const customQuestionSchema = z.object({
  question_text: z.string().min(1, 'Question text is required').max(500, 'Question is too long'),
  question_type: z.enum(['text', 'textarea', 'select', 'multiselect', 'checkbox', 'radio', 'email', 'phone', 'number', 'date', 'time', 'url']),
  is_required: z.boolean().optional(),
  order: z.number().min(0, 'Order cannot be negative'),
  options: z.array(z.string()).optional(),
  conditions: z.any().optional(),
  validation_rules: z.any().optional(),
})

// Booking Forms
export const bookingSchema = z.object({
  invitee_name: z.string().min(1, 'Name is required').max(200, 'Name is too long'),
  invitee_email: z.string().email('Please enter a valid email address'),
  invitee_phone: z.string().optional(),
  invitee_timezone: z.string().min(1, 'Timezone is required'),
  attendee_count: z.number().min(1, 'At least 1 attendee required').optional(),
  start_time: z.string().min(1, 'Start time is required'),
  custom_answers: z.record(z.any()).optional(),
  attendees_data: z.array(z.object({
    name: z.string().min(1, 'Name is required'),
    email: z.string().email('Please enter a valid email address'),
    phone: z.string().optional(),
    custom_answers: z.record(z.any()).optional(),
  })).optional(),
})

// Availability Forms
export const availabilityRuleSchema = z.object({
  day_of_week: z.number().min(0, 'Invalid day').max(6, 'Invalid day'),
  start_time: z.string().min(1, 'Start time is required'),
  end_time: z.string().min(1, 'End time is required'),
  event_types: z.array(z.string()).optional(),
  is_active: z.boolean().optional(),
})

export const dateOverrideSchema = z.object({
  date: z.string().min(1, 'Date is required'),
  is_available: z.boolean(),
  start_time: z.string().optional(),
  end_time: z.string().optional(),
  event_types: z.array(z.string()).optional(),
  reason: z.string().max(200, 'Reason is too long').optional(),
  is_active: z.boolean().optional(),
}).refine(data => {
  if (data.is_available && (!data.start_time || !data.end_time)) {
    return false
  }
  return true
}, {
  message: 'Start time and end time are required when available',
  path: ['start_time'],
})

export const blockedTimeSchema = z.object({
  start_datetime: z.string().min(1, 'Start time is required'),
  end_datetime: z.string().min(1, 'End time is required'),
  reason: z.string().max(200, 'Reason is too long').optional(),
  is_active: z.boolean().optional(),
})

export const recurringBlockedTimeSchema = z.object({
  name: z.string().min(1, 'Name is required').max(200, 'Name is too long'),
  day_of_week: z.number().min(0, 'Invalid day').max(6, 'Invalid day'),
  start_time: z.string().min(1, 'Start time is required'),
  end_time: z.string().min(1, 'End time is required'),
  start_date: z.string().optional(),
  end_date: z.string().optional(),
  is_active: z.boolean().optional(),
}).refine(data => {
  if (data.start_date && data.end_date && data.start_date > data.end_date) {
    return false
  }
  return true
}, {
  message: 'Start date must be before end date',
  path: ['end_date'],
})

export const bufferTimeSchema = z.object({
  default_buffer_before: z.number().min(0, 'Cannot be negative').max(120, 'Maximum 2 hours'),
  default_buffer_after: z.number().min(0, 'Cannot be negative').max(120, 'Maximum 2 hours'),
  minimum_gap: z.number().min(0, 'Cannot be negative').max(60, 'Maximum 1 hour'),
  slot_interval_minutes: z.number().min(5, 'Minimum 5 minutes').max(60, 'Maximum 1 hour'),
})

// Workflow Forms
export const workflowSchema = z.object({
  name: z.string().min(1, 'Workflow name is required').max(200, 'Name is too long'),
  description: z.string().optional(),
  trigger: z.enum(['booking_created', 'booking_cancelled', 'booking_completed', 'before_meeting', 'after_meeting']),
  event_types: z.array(z.string()).optional(),
  delay_minutes: z.number().min(0, 'Cannot be negative').max(10080, 'Maximum 1 week'),
  is_active: z.boolean().optional(),
})

export const workflowActionSchema = z.object({
  name: z.string().min(1, 'Action name is required').max(200, 'Name is too long'),
  action_type: z.enum(['send_email', 'send_sms', 'webhook', 'update_booking']),
  order: z.number().min(0, 'Order cannot be negative'),
  recipient: z.enum(['organizer', 'invitee', 'both', 'custom']).optional(),
  custom_email: z.string().email('Please enter a valid email address').optional(),
  subject: z.string().max(200, 'Subject is too long').optional(),
  message: z.string().optional(),
  webhook_url: z.string().url('Must be a valid URL').optional(),
  webhook_data: z.record(z.any()).optional(),
  conditions: z.any().optional(),
  update_booking_fields: z.record(z.any()).optional(),
  is_active: z.boolean().optional(),
}).refine(data => {
  // Custom validation based on action type
  if (data.action_type === 'send_email' || data.action_type === 'send_sms') {
    if (data.recipient === 'custom' && !data.custom_email) {
      return false
    }
  }
  if (data.action_type === 'webhook' && !data.webhook_url) {
    return false
  }
  if (data.action_type === 'update_booking' && !data.update_booking_fields) {
    return false
  }
  return true
}, {
  message: 'Required fields missing for action type',
})

// Notification Forms
export const notificationTemplateSchema = z.object({
  name: z.string().min(1, 'Template name is required').max(200, 'Name is too long'),
  template_type: z.enum(['booking_confirmation', 'booking_reminder', 'booking_cancellation', 'booking_rescheduled', 'follow_up', 'custom']),
  notification_type: z.enum(['email', 'sms']),
  subject: z.string().max(200, 'Subject is too long').optional(),
  message: z.string().min(1, 'Message is required'),
  is_active: z.boolean().optional(),
  is_default: z.boolean().optional(),
})

export const notificationPreferenceSchema = z.object({
  booking_confirmations_email: z.boolean().optional(),
  booking_reminders_email: z.boolean().optional(),
  booking_cancellations_email: z.boolean().optional(),
  daily_agenda_email: z.boolean().optional(),
  booking_confirmations_sms: z.boolean().optional(),
  booking_reminders_sms: z.boolean().optional(),
  booking_cancellations_sms: z.boolean().optional(),
  reminder_minutes_before: z.number().min(0, 'Cannot be negative').max(10080, 'Maximum 1 week'),
  daily_agenda_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Invalid time format'),
  dnd_enabled: z.boolean().optional(),
  dnd_start_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Invalid time format').optional(),
  dnd_end_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Invalid time format').optional(),
  exclude_weekends_reminders: z.boolean().optional(),
  exclude_weekends_agenda: z.boolean().optional(),
  preferred_notification_method: z.enum(['email', 'sms', 'both']).optional(),
  max_reminders_per_day: z.number().min(1, 'At least 1 reminder').max(50, 'Maximum 50 reminders'),
})

// Contact Forms
export const contactSchema = z.object({
  first_name: z.string().min(1, 'First name is required').max(100, 'Name is too long'),
  last_name: z.string().max(100, 'Name is too long').optional(),
  email: z.string().email('Please enter a valid email address'),
  phone: z.string().max(20, 'Phone number is too long').optional(),
  company: z.string().max(200, 'Company name is too long').optional(),
  job_title: z.string().max(200, 'Job title is too long').optional(),
  notes: z.string().optional(),
  tags: z.array(z.string()).optional(),
  is_active: z.boolean().optional(),
})

export const contactGroupSchema = z.object({
  name: z.string().min(1, 'Group name is required').max(100, 'Name is too long'),
  description: z.string().optional(),
  color: z.string().regex(/^#[0-9A-F]{6}$/i, 'Must be a valid hex color').optional(),
  contact_ids: z.array(z.string()).optional(),
})

// Profile Forms
export const profileSchema = z.object({
  display_name: z.string().min(1, 'Display name is required').max(100, 'Name is too long'),
  bio: z.string().max(500, 'Bio is too long').optional(),
  phone: z.string().regex(/^\+?1?\d{9,15}$/, 'Invalid phone number format').optional(),
  website: z.string().url('Must be a valid URL').optional().or(z.literal('')),
  company: z.string().max(100, 'Company name is too long').optional(),
  job_title: z.string().max(100, 'Job title is too long').optional(),
  timezone_name: z.string().min(1, 'Timezone is required'),
  language: z.string().min(1, 'Language is required'),
  date_format: z.string().min(1, 'Date format is required'),
  time_format: z.string().min(1, 'Time format is required'),
  brand_color: z.string().regex(/^#[0-9A-F]{6}$/i, 'Must be a valid hex color'),
  public_profile: z.boolean().optional(),
  show_phone: z.boolean().optional(),
  show_email: z.boolean().optional(),
  reasonable_hours_start: z.number().min(0, 'Invalid hour').max(23, 'Invalid hour'),
  reasonable_hours_end: z.number().min(1, 'Invalid hour').max(24, 'Invalid hour'),
})

// Integration Forms
export const webhookIntegrationSchema = z.object({
  name: z.string().min(1, 'Webhook name is required').max(100, 'Name is too long'),
  webhook_url: z.string().url('Must be a valid URL'),
  events: z.array(z.string()).min(1, 'At least one event must be selected'),
  secret_key: z.string().optional(),
  headers: z.record(z.string()).optional(),
  is_active: z.boolean().optional(),
  retry_failed: z.boolean().optional(),
  max_retries: z.number().min(0, 'Cannot be negative').max(10, 'Maximum 10 retries').optional(),
})

// MFA Forms
export const mfaSetupSchema = z.object({
  device_type: z.enum(['totp', 'sms', 'backup']),
  device_name: z.string().min(1, 'Device name is required').max(100, 'Name is too long'),
  phone_number: z.string().regex(/^\+?1?\d{9,15}$/, 'Invalid phone number format').optional(),
}).refine(data => {
  if (data.device_type === 'sms' && !data.phone_number) {
    return false
  }
  return true
}, {
  message: 'Phone number is required for SMS devices',
  path: ['phone_number'],
})

export const mfaVerificationSchema = z.object({
  otp_code: z.string().length(6, 'OTP code must be 6 digits').regex(/^\d+$/, 'OTP code must contain only digits'),
  device_id: z.string().optional(),
})

// Team Management Forms
export const invitationSchema = z.object({
  invited_email: z.string().email('Please enter a valid email address'),
  role: z.string().min(1, 'Role is required'),
  message: z.string().max(500, 'Message is too long').optional(),
})

export const invitationResponseSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  action: z.enum(['accept', 'decline']),
  first_name: z.string().min(1, 'First name is required').optional(),
  last_name: z.string().min(1, 'Last name is required').optional(),
  password: z.string().min(8, 'Password must be at least 8 characters').optional(),
  password_confirm: z.string().optional(),
}).refine(data => {
  if (data.action === 'accept' && data.password && data.password !== data.password_confirm) {
    return false
  }
  return true
}, {
  message: 'Passwords do not match',
  path: ['password_confirm'],
})

// Form data types (inferred from schemas)
export type LoginFormData = z.infer<typeof loginSchema>
export type RegisterFormData = z.infer<typeof registerSchema>
export type ChangePasswordFormData = z.infer<typeof changePasswordSchema>
export type PasswordResetRequestFormData = z.infer<typeof passwordResetRequestSchema>
export type PasswordResetConfirmFormData = z.infer<typeof passwordResetConfirmSchema>
export type EventTypeFormData = z.infer<typeof eventTypeSchema>
export type CustomQuestionFormData = z.infer<typeof customQuestionSchema>
export type BookingFormData = z.infer<typeof bookingSchema>
export type AvailabilityRuleFormData = z.infer<typeof availabilityRuleSchema>
export type DateOverrideFormData = z.infer<typeof dateOverrideSchema>
export type BlockedTimeFormData = z.infer<typeof blockedTimeSchema>
export type RecurringBlockedTimeFormData = z.infer<typeof recurringBlockedTimeSchema>
export type BufferTimeFormData = z.infer<typeof bufferTimeSchema>
export type WorkflowFormData = z.infer<typeof workflowSchema>
export type WorkflowActionFormData = z.infer<typeof workflowActionSchema>
export type NotificationTemplateFormData = z.infer<typeof notificationTemplateSchema>
export type NotificationPreferenceFormData = z.infer<typeof notificationPreferenceSchema>
export type ContactFormData = z.infer<typeof contactSchema>
export type ContactGroupFormData = z.infer<typeof contactGroupSchema>
export type ProfileFormData = z.infer<typeof profileSchema>
export type WebhookIntegrationFormData = z.infer<typeof webhookIntegrationSchema>
export type MFASetupFormData = z.infer<typeof mfaSetupSchema>
export type MFAVerificationFormData = z.infer<typeof mfaVerificationSchema>
export type InvitationFormData = z.infer<typeof invitationSchema>
export type InvitationResponseFormData = z.infer<typeof invitationResponseSchema>
export type ContactFormData = z.infer<typeof contactSchema>
export type ContactGroupFormData = z.infer<typeof contactGroupSchema>

// Notification Forms
export const notificationTemplateSchema = z.object({
  name: z.string().min(1, 'Template name is required').max(200, 'Name is too long'),
  template_type: z.enum(['booking_confirmation', 'booking_reminder', 'booking_cancellation', 'booking_rescheduled', 'follow_up', 'custom']),
  notification_type: z.enum(['email', 'sms']),
  subject: z.string().max(200, 'Subject is too long').optional(),
  message: z.string().min(1, 'Message is required'),
  is_active: z.boolean().optional(),
  is_default: z.boolean().optional(),
})

export const sendNotificationSchema = z.object({
  notification_type: z.enum(['email', 'sms']),
  template_id: z.string().optional(),
  recipient_email: z.string().email('Please enter a valid email address').optional(),
  recipient_phone: z.string().optional(),
  subject: z.string().max(200, 'Subject is too long').optional(),
  message: z.string().min(1, 'Message is required'),
  booking_id: z.string().optional(),
  send_immediately: z.boolean().optional(),
  scheduled_for: z.string().optional(),
}).refine(data => {
  if (data.notification_type === 'email' && !data.recipient_email) {
    return false
  }
  if (data.notification_type === 'sms' && !data.recipient_phone) {
    return false
  }
  return true
}, {
  message: 'Recipient is required for the selected notification type',
})
export type NotificationTemplateFormData = z.infer<typeof notificationTemplateSchema>
export type NotificationPreferenceFormData = z.infer<typeof notificationPreferenceSchema>
export type SendNotificationFormData = z.infer<typeof sendNotificationSchema>

// Form state types
export interface FormState<T = any> {
  data: T
  errors: Record<string, string>
  isSubmitting: boolean
  isValid: boolean
  isDirty: boolean
}

export interface FormFieldState {
  value: any
  error?: string
  touched: boolean
  dirty: boolean
}

// Validation result types
export interface ValidationResult {
  isValid: boolean
  errors: Record<string, string>
}

export interface FieldValidationResult {
  isValid: boolean
  error?: string
}