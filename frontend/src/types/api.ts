// Base API types
export interface ApiResponse<T = any> {
  data?: T
  message?: string
  error?: string
  errors?: Record<string, string[]>
  details?: any
}

export interface PaginatedResponse<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface ApiError {
  message: string
  status: number
  code?: string
  details?: any
}

// Request types
export interface LoginRequest {
  email: string
  password: string
  remember_me?: boolean
}

export interface RegisterRequest {
  email: string
  first_name: string
  last_name: string
  password: string
  password_confirm: string
  terms_accepted: boolean
}

export interface ChangePasswordRequest {
  old_password: string
  new_password: string
  new_password_confirm: string
}

export interface PasswordResetRequest {
  email: string
}

export interface PasswordResetConfirmRequest {
  token: string
  new_password: string
  new_password_confirm: string
}

export interface EmailVerificationRequest {
  token: string
}

export interface CreateEventTypeRequest {
  name: string
  description?: string
  duration: number
  max_attendees?: number
  enable_waitlist?: boolean
  is_active?: boolean
  is_private?: boolean
  min_scheduling_notice?: number
  max_scheduling_horizon?: number
  buffer_time_before?: number
  buffer_time_after?: number
  max_bookings_per_day?: number
  slot_interval_minutes?: number
  location_type: string
  location_details?: string
  redirect_url_after_booking?: string
  questions_data?: CustomQuestionData[]
}

export interface CustomQuestionData {
  question_text: string
  question_type: string
  is_required?: boolean
  order?: number
  options?: string[]
  conditions?: any
  validation_rules?: any
}

export interface CreateBookingRequest {
  organizer_slug: string
  event_type_slug: string
  invitee_name: string
  invitee_email: string
  invitee_phone?: string
  invitee_timezone: string
  attendee_count?: number
  start_time: string
  custom_answers?: Record<string, any>
  attendees_data?: AttendeeData[]
}

export interface AttendeeData {
  name: string
  email: string
  phone?: string
  custom_answers?: Record<string, any>
}

export interface AvailabilityRuleRequest {
  day_of_week: number
  start_time: string
  end_time: string
  event_types?: string[]
  is_active?: boolean
}

export interface DateOverrideRequest {
  date: string
  is_available: boolean
  start_time?: string
  end_time?: string
  event_types?: string[]
  reason?: string
  is_active?: boolean
}

export interface BlockedTimeRequest {
  start_datetime: string
  end_datetime: string
  reason?: string
  is_active?: boolean
}

export interface RecurringBlockedTimeRequest {
  name: string
  day_of_week: number
  start_time: string
  end_time: string
  start_date?: string
  end_date?: string
  is_active?: boolean
}

export interface BufferTimeRequest {
  default_buffer_before: number
  default_buffer_after: number
  minimum_gap: number
  slot_interval_minutes: number
}

export interface WorkflowRequest {
  name: string
  description?: string
  trigger: string
  event_types?: string[]
  delay_minutes?: number
  is_active?: boolean
}

export interface WorkflowActionRequest {
  name: string
  action_type: string
  order: number
  recipient?: string
  custom_email?: string
  subject?: string
  message?: string
  webhook_url?: string
  webhook_data?: Record<string, any>
  conditions?: any
  update_booking_fields?: Record<string, any>
  is_active?: boolean
}

export interface NotificationTemplateRequest {
  name: string
  template_type: string
  notification_type: string
  subject?: string
  message: string
  is_active?: boolean
  is_default?: boolean
}

export interface NotificationPreferenceRequest {
  booking_confirmations_email?: boolean
  booking_reminders_email?: boolean
  booking_cancellations_email?: boolean
  daily_agenda_email?: boolean
  booking_confirmations_sms?: boolean
  booking_reminders_sms?: boolean
  booking_cancellations_sms?: boolean
  reminder_minutes_before?: number
  daily_agenda_time?: string
  dnd_enabled?: boolean
  dnd_start_time?: string
  dnd_end_time?: string
  exclude_weekends_reminders?: boolean
  exclude_weekends_agenda?: boolean
  preferred_notification_method?: string
  max_reminders_per_day?: number
}

export interface ContactRequest {
  first_name: string
  last_name?: string
  email: string
  phone?: string
  company?: string
  job_title?: string
  notes?: string
  tags?: string[]
  is_active?: boolean
}

export interface ContactGroupRequest {
  name: string
  description?: string
  color?: string
  contact_ids?: string[]
}

export interface WebhookIntegrationRequest {
  name: string
  webhook_url: string
  events: string[]
  secret_key?: string
  headers?: Record<string, string>
  is_active?: boolean
  retry_failed?: boolean
  max_retries?: number
}

// Query parameters
export interface AvailableSlotsParams {
  start_date: string
  end_date: string
  timezone?: string
  attendee_count?: number
  invitee_timezones?: string[]
}

export interface BookingListParams {
  status?: string
  start_date?: string
  end_date?: string
  page?: number
  page_size?: number
}

export interface ContactListParams {
  search?: string
  group?: string
  tags?: string
  is_active?: boolean
  page?: number
  page_size?: number
}

// Response types
export interface LoginResponse {
  user: User
  token: string
}

export interface RegisterResponse {
  user: User
  token: string
  message: string
}

export interface AvailableSlotsResponse {
  organizer_slug: string
  event_type_slug: string
  start_date: string
  end_date: string
  invitee_timezone: string
  attendee_count: number
  available_slots: AvailableSlot[]
  cache_hit: boolean
  total_slots: number
  computation_time_ms: number
  multi_invitee_mode?: boolean
  invitee_timezones?: string[]
}

export interface BookingResponse {
  id: string
  event_type: EventType
  organizer: User
  invitee_name: string
  invitee_email: string
  invitee_phone?: string
  invitee_timezone: string
  attendee_count: number
  start_time: string
  end_time: string
  status: string
  status_display: string
  duration_minutes: number
  custom_answers: Record<string, any>
  meeting_link?: string
  meeting_id?: string
  meeting_password?: string
  attendees: Attendee[]
  can_cancel: boolean
  can_reschedule: boolean
  access_token: string
  management_url: string
  redirect_url?: string
  created_at: string
  updated_at: string
}

export interface PublicOrganizerResponse {
  organizer_slug: string
  display_name: string
  bio?: string
  profile_picture?: string
  company?: string
  website?: string
  timezone: string
  brand_color: string
  event_types: PublicEventType[]
}

export interface PublicBookingPageResponse {
  name: string
  event_type_slug: string
  description?: string
  duration: number
  max_attendees: number
  enable_waitlist: boolean
  location_type: string
  location_details?: string
  min_scheduling_notice: number
  max_scheduling_horizon: number
  organizer_name: string
  organizer_bio?: string
  organizer_picture?: string
  organizer_company?: string
  organizer_timezone: string
  questions: CustomQuestion[]
  is_group_event: boolean
  available_slots: AvailableSlot[]
  custom_questions: CustomQuestion[]
  cache_hit: boolean
  total_slots: number
  performance_metrics: Record<string, any>
  search_params: Record<string, any>
}

// Import model types
import type {
  User,
  EventType,
  Booking,
  Attendee,
  CustomQuestion,
  AvailableSlot,
  PublicEventType,
  AvailabilityRule,
  DateOverrideRule,
  BlockedTime,
  RecurringBlockedTime,
  BufferTime,
  Workflow,
  WorkflowAction,
  WorkflowExecution,
  NotificationTemplate,
  NotificationLog,
  NotificationPreference,
  Contact,
  ContactGroup,
  CalendarIntegration,
  VideoConferenceIntegration,
  WebhookIntegration,
} from './models'