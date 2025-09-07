// User & Authentication Models
export interface User {
  id: string
  email: string
  first_name: string
  last_name: string
  full_name: string
  is_organizer: boolean
  is_email_verified: boolean
  is_phone_verified: boolean
  is_mfa_enabled: boolean
  account_status: string
  roles: Role[]
  profile: Profile
  last_login: string | null
  date_joined: string
}

export interface Profile {
  organizer_slug: string
  display_name: string
  bio?: string
  profile_picture?: string
  phone?: string
  website?: string
  company?: string
  job_title?: string
  timezone_name: string
  language: string
  date_format: string
  time_format: string
  brand_color: string
  brand_logo?: string
  public_profile: boolean
  show_phone: boolean
  show_email: boolean
  reasonable_hours_start: number
  reasonable_hours_end: number
}

export interface Role {
  id: string
  name: string
  role_type: string
  description?: string
  parent?: string
  parent_name?: string
  children_count: number
  role_permissions: Permission[]
  total_permissions: number
  is_system_role: boolean
}

export interface Permission {
  id: string
  codename: string
  name: string
  description?: string
  category: string
}

export interface Invitation {
  id: string
  invited_email: string
  role: string
  role_name: string
  message?: string
  status: string
  invited_by_name: string
  created_at: string
  expires_at: string
}

export interface AuditLog {
  id: string
  user_email: string
  action: string
  action_display: string
  description: string
  ip_address?: string
  user_agent?: string
  metadata: Record<string, any>
  created_at: string
}

export interface UserSession {
  id: string
  session_key: string
  ip_address: string
  country?: string
  city?: string
  location: string
  user_agent: string
  device_info: Record<string, any>
  created_at: string
  last_activity: string
  expires_at: string
  is_active: boolean
  is_current: boolean
  is_expired: boolean
}

export interface MFADevice {
  id: string
  device_type: string
  device_type_display: string
  name: string
  phone_number?: string
  is_active: boolean
  is_primary: boolean
  last_used_at?: string
  created_at: string
}

// Event & Booking Models
export interface EventType {
  id: string
  organizer: User
  name: string
  event_type_slug: string
  description?: string
  duration: number
  max_attendees: number
  enable_waitlist: boolean
  is_active: boolean
  is_private: boolean
  min_scheduling_notice: number
  max_scheduling_horizon: number
  buffer_time_before: number
  buffer_time_after: number
  max_bookings_per_day?: number
  slot_interval_minutes: number
  recurrence_type: string
  recurrence_rule?: string
  max_occurrences?: number
  recurrence_end_date?: string
  location_type: string
  location_details?: string
  redirect_url_after_booking?: string
  confirmation_workflow?: string
  reminder_workflow?: string
  cancellation_workflow?: string
  questions: CustomQuestion[]
  is_group_event: boolean
  total_duration_with_buffers: number
  created_at: string
  updated_at: string
}

export interface PublicEventType {
  name: string
  event_type_slug: string
  description?: string
  duration: number
  max_attendees: number
  enable_waitlist: boolean
  location_type: string
  location_details?: string
  is_group_event: boolean
}

export interface CustomQuestion {
  id: string
  question_text: string
  question_type: string
  question_type_display: string
  is_required: boolean
  order: number
  options?: string[]
  conditions?: any
  validation_rules?: any
}

export interface Booking {
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
  recurrence_id?: string
  is_recurring_exception: boolean
  recurrence_sequence?: number
  custom_answers: Record<string, any>
  meeting_link?: string
  meeting_id?: string
  meeting_password?: string
  calendar_sync_status: string
  attendees: Attendee[]
  duration_minutes: number
  can_cancel: boolean
  can_reschedule: boolean
  is_access_token_valid: boolean
  cancelled_at?: string
  cancelled_by?: string
  cancellation_reason?: string
  rescheduled_at?: string
  created_at: string
  updated_at: string
}

export interface Attendee {
  id: string
  name: string
  email: string
  phone?: string
  status: string
  status_display: string
  custom_answers: Record<string, any>
  joined_at: string
  cancelled_at?: string
  cancellation_reason?: string
}

export interface WaitlistEntry {
  id: string
  event_type_name: string
  desired_start_time: string
  desired_end_time: string
  invitee_name: string
  invitee_email: string
  invitee_phone?: string
  invitee_timezone: string
  notify_when_available: boolean
  expires_at: string
  status: string
  status_display: string
  is_expired: boolean
  custom_answers: Record<string, any>
  notified_at?: string
  created_at: string
}

export interface AvailableSlot {
  start_time: string
  end_time: string
  duration_minutes: number
  local_start_time?: string
  local_end_time?: string
  invitee_times?: Record<string, any>
  fairness_score?: number
  available_spots?: number
}

// Availability Models
export interface AvailabilityRule {
  id: string
  day_of_week: number
  day_of_week_display: string
  start_time: string
  end_time: string
  event_types: string[]
  event_types_count: number
  spans_midnight: boolean
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface DateOverrideRule {
  id: string
  date: string
  is_available: boolean
  start_time?: string
  end_time?: string
  event_types: string[]
  event_types_count: number
  spans_midnight: boolean
  reason?: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface BlockedTime {
  id: string
  start_datetime: string
  end_datetime: string
  reason?: string
  source: string
  source_display: string
  external_id?: string
  external_updated_at?: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface RecurringBlockedTime {
  id: string
  name: string
  day_of_week: number
  day_of_week_display: string
  start_time: string
  end_time: string
  start_date?: string
  end_date?: string
  spans_midnight: boolean
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface BufferTime {
  default_buffer_before: number
  default_buffer_after: number
  minimum_gap: number
  slot_interval_minutes: number
  created_at: string
  updated_at: string
}

export interface AvailabilityStats {
  total_rules: number
  active_rules: number
  total_overrides: number
  total_blocks: number
  total_recurring_blocks: number
  average_weekly_hours: number
  busiest_day: string
  daily_hours: Record<string, number>
  cache_hit_rate: number
  performance_summary?: Record<string, any>
}

// Integration Models
export interface CalendarIntegration {
  id: string
  provider: string
  provider_display: string
  provider_email?: string
  calendar_id?: string
  is_active: boolean
  sync_enabled: boolean
  is_token_expired: boolean
  created_at: string
  updated_at: string
}

export interface VideoConferenceIntegration {
  id: string
  provider: string
  provider_display: string
  provider_email?: string
  is_active: boolean
  auto_generate_links: boolean
  is_token_expired: boolean
  created_at: string
  updated_at: string
}

export interface WebhookIntegration {
  id: string
  name: string
  webhook_url: string
  events: string[]
  secret_key?: string
  headers?: Record<string, string>
  is_active: boolean
  retry_failed: boolean
  max_retries: number
  created_at: string
  updated_at: string
}

export interface IntegrationLog {
  id: string
  log_type: string
  log_type_display: string
  integration_type: string
  booking_id?: string
  message: string
  details: Record<string, any>
  success: boolean
  created_at: string
}

// Workflow Models
export interface Workflow {
  id: string
  name: string
  description?: string
  trigger: string
  trigger_display: string
  event_types_count: number
  delay_minutes: number
  is_active: boolean
  success_rate: number
  execution_stats: {
    total_executions: number
    successful_executions: number
    failed_executions: number
    last_executed_at?: string
  }
  actions: WorkflowAction[]
  created_at: string
  updated_at: string
}

export interface WorkflowAction {
  id: string
  name: string
  action_type: string
  action_type_display: string
  order: number
  recipient: string
  recipient_display: string
  custom_email?: string
  subject?: string
  message?: string
  webhook_url?: string
  webhook_data?: Record<string, any>
  conditions?: any
  update_booking_fields?: Record<string, any>
  is_active: boolean
  success_rate: number
  execution_stats: {
    total_executions: number
    successful_executions: number
    failed_executions: number
    last_executed_at?: string
  }
  created_at: string
  updated_at: string
}

export interface WorkflowExecution {
  id: string
  workflow_name: string
  booking_invitee?: string
  status: string
  status_display: string
  started_at?: string
  completed_at?: string
  error_message?: string
  actions_executed: number
  actions_failed: number
  execution_log: any[]
  execution_summary: any
  execution_time_seconds?: number
  created_at: string
  updated_at: string
}

export interface WorkflowTemplate {
  id: string
  name: string
  description: string
  category: string
  category_display: string
  template_data: any
  is_public: boolean
  usage_count: number
  created_at: string
  updated_at: string
}

// Notification Models
export interface NotificationTemplate {
  id: string
  name: string
  template_type: string
  template_type_display: string
  notification_type: string
  notification_type_display: string
  subject?: string
  message: string
  is_active: boolean
  is_default: boolean
  created_at: string
  updated_at: string
}

export interface NotificationLog {
  id: string
  booking_id?: string
  template_name?: string
  notification_type: string
  notification_type_display: string
  recipient_email?: string
  recipient_phone?: string
  subject?: string
  status: string
  status_display: string
  sent_at?: string
  delivered_at?: string
  opened_at?: string
  clicked_at?: string
  error_message?: string
  retry_count: number
  created_at: string
  updated_at: string
}

export interface NotificationPreference {
  booking_confirmations_email: boolean
  booking_reminders_email: boolean
  booking_cancellations_email: boolean
  daily_agenda_email: boolean
  booking_confirmations_sms: boolean
  booking_reminders_sms: boolean
  booking_cancellations_sms: boolean
  reminder_minutes_before: number
  daily_agenda_time: string
  dnd_enabled: boolean
  dnd_start_time: string
  dnd_end_time: string
  exclude_weekends_reminders: boolean
  exclude_weekends_agenda: boolean
  preferred_notification_method: string
  max_reminders_per_day: number
  created_at: string
  updated_at: string
}

export interface NotificationSchedule {
  id: string
  booking_id?: string
  schedule_type: string
  schedule_type_display: string
  notification_type: string
  notification_type_display: string
  scheduled_for: string
  status: string
  status_display: string
  recipient_email?: string
  recipient_phone?: string
  subject?: string
  sent_at?: string
  error_message?: string
  created_at: string
  updated_at: string
}

// Contact Models
export interface Contact {
  id: string
  first_name: string
  last_name?: string
  full_name: string
  email: string
  phone?: string
  company?: string
  job_title?: string
  notes?: string
  tags: string[]
  total_bookings: number
  last_booking_date?: string
  groups_count: number
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface ContactGroup {
  id: string
  name: string
  description?: string
  color: string
  contact_count: number
  contacts: Contact[]
  created_at: string
  updated_at: string
}

export interface ContactInteraction {
  id: string
  contact_name: string
  interaction_type: string
  interaction_type_display: string
  description: string
  booking_id?: string
  metadata: Record<string, any>
  created_at: string
}

// Statistics Models
export interface BookingAnalytics {
  total_bookings: number
  confirmed_bookings: number
  cancelled_bookings: number
  completed_bookings: number
  no_show_bookings: number
  calendar_sync_success: number
  calendar_sync_failed: number
  calendar_sync_pending: number
  bookings_by_event_type: Array<{
    event_type__name: string
    count: number
  }>
  cancellations_by_actor: Array<{
    cancelled_by: string
    count: number
  }>
  group_event_stats: {
    total_group_bookings: number
    average_attendees: number
  }
}

export interface ContactStats {
  total_contacts: number
  active_contacts: number
  total_groups: number
  recent_interactions: number
  top_companies: Array<{
    company: string
    count: number
  }>
  booking_frequency: {
    this_month: number
    last_month: number
    this_year: number
  }
}

export interface NotificationStats {
  total_notifications: number
  total_sent: number
  total_failed: number
  total_pending: number
  total_delivered: number
  total_opened: number
  total_clicked: number
  email_count: number
  sms_count: number
  email_delivery_rate: number
  email_open_rate: number
  email_click_rate: number
  sms_delivery_rate: number
  recent_activity: Record<string, number>
  top_templates: Array<{
    template__name: string
    usage_count: number
  }>
  preferences: Record<string, any>
}

export interface WorkflowStats {
  total_workflows: number
  active_workflows: number
  inactive_workflows: number
  execution_stats_30_days: {
    total_executions: number
    successful_executions: number
    failed_executions: number
    success_rate: number
  }
  top_performing_workflows: Array<{
    workflow_id: string
    workflow_name: string
    total_executions: number
    successful_executions: number
    success_rate: number
    last_executed?: string
  }>
  problematic_workflows: Array<{
    workflow_id: string
    workflow_name: string
    total_executions: number
    successful_executions: number
    success_rate: number
    last_executed?: string
  }>
}

export interface IntegrationHealth {
  organizer_id: string
  organizer_email: string
  timestamp: string
  calendar_integrations: Array<{
    provider: string
    is_active: boolean
    sync_enabled: boolean
    token_expired: boolean
    last_sync?: string
    sync_errors: number
    health: string
  }>
  video_integrations: Array<{
    provider: string
    is_active: boolean
    auto_generate_links: boolean
    token_expired: boolean
    api_calls_today: number
    health: string
  }>
  overall_health: string
}

// Dashboard Models
export interface DashboardStats {
  total_bookings: number
  upcoming_bookings: number
  total_event_types: number
  active_event_types: number
  recent_bookings: Booking[]
  booking_trends: Array<{
    date: string
    count: number
  }>
  popular_event_types: Array<{
    name: string
    booking_count: number
  }>
  calendar_sync_health: {
    total: number
    successful: number
    failed: number
    success_rate: number
  }
  notification_health: {
    total: number
    sent: number
    failed: number
    success_rate: number
  }
}