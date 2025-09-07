import { apiClient } from './api'
import type {
  EventType,
  CreateEventTypeRequest,
  Booking,
  CreateBookingRequest,
  BookingResponse,
  AvailableSlotsParams,
  AvailableSlotsResponse,
  BookingListParams,
  PaginatedResponse,
  PublicOrganizerResponse,
  PublicBookingPageResponse,
  BookingAnalytics,
  WaitlistEntry,
  Attendee,
} from '@/types'

export const eventsService = {
  // Event Types
  getEventTypes: (): Promise<EventType[]> =>
    apiClient.get('/events/event-types/'),

  getEventType: (id: string): Promise<EventType> =>
    apiClient.get(`/events/event-types/${id}/`),

  createEventType: (data: CreateEventTypeRequest): Promise<EventType> =>
    apiClient.post('/events/event-types/', data),

  updateEventType: (id: string, data: Partial<CreateEventTypeRequest>): Promise<EventType> =>
    apiClient.patch(`/events/event-types/${id}/`, data),

  deleteEventType: (id: string): Promise<void> =>
    apiClient.delete(`/events/event-types/${id}/`),

  // Public Pages
  getPublicOrganizerPage: (organizerSlug: string): Promise<PublicOrganizerResponse> =>
    apiClient.get(`/events/public/${organizerSlug}/`),

  getPublicEventTypePage: (
    organizerSlug: string,
    eventTypeSlug: string,
    params?: {
      start_date?: string
      end_date?: string
      timezone?: string
      attendee_count?: number
    }
  ): Promise<PublicBookingPageResponse> => {
    const queryParams = new URLSearchParams()
    if (params?.start_date) queryParams.append('start_date', params.start_date)
    if (params?.end_date) queryParams.append('end_date', params.end_date)
    if (params?.timezone) queryParams.append('timezone', params.timezone)
    if (params?.attendee_count) queryParams.append('attendee_count', params.attendee_count.toString())
    
    const queryString = queryParams.toString()
    const url = `/events/public/${organizerSlug}/${eventTypeSlug}/${queryString ? `?${queryString}` : ''}`
    
    return apiClient.get(url)
  },

  // Available Slots
  getAvailableSlots: (
    organizerSlug: string,
    eventTypeSlug: string,
    params: AvailableSlotsParams
  ): Promise<AvailableSlotsResponse> => {
    const queryParams = new URLSearchParams()
    queryParams.append('start_date', params.start_date)
    queryParams.append('end_date', params.end_date)
    if (params.timezone) queryParams.append('timezone', params.timezone)
    if (params.attendee_count) queryParams.append('attendee_count', params.attendee_count.toString())
    if (params.invitee_timezones) {
      queryParams.append('invitee_timezones', params.invitee_timezones.join(','))
    }

    return apiClient.get(`/events/slots/${organizerSlug}/${eventTypeSlug}/?${queryParams.toString()}`)
  },

  // Bookings
  getBookings: (params?: BookingListParams): Promise<PaginatedResponse<Booking>> => {
    const queryParams = new URLSearchParams()
    if (params?.status) queryParams.append('status', params.status)
    if (params?.start_date) queryParams.append('start_date', params.start_date)
    if (params?.end_date) queryParams.append('end_date', params.end_date)
    if (params?.page) queryParams.append('page', params.page.toString())
    if (params?.page_size) queryParams.append('page_size', params.page_size.toString())

    const queryString = queryParams.toString()
    return apiClient.get(`/events/bookings/${queryString ? `?${queryString}` : ''}`)
  },

  getBooking: (id: string): Promise<Booking> =>
    apiClient.get(`/events/bookings/${id}/`),

  updateBooking: (id: string, data: {
    status?: string
    cancellation_reason?: string
    meeting_link?: string
    meeting_id?: string
    meeting_password?: string
    custom_answers?: Record<string, any>
  }): Promise<Booking> =>
    apiClient.patch(`/events/bookings/${id}/`, data),

  createBooking: (data: CreateBookingRequest): Promise<BookingResponse> =>
    apiClient.post('/events/bookings/create/', data),

  // Booking Management (Public)
  getBookingByToken: (accessToken: string): Promise<{
    id: string
    event_type_name: string
    organizer_name: string
    invitee_name: string
    invitee_email: string
    invitee_phone?: string
    invitee_timezone: string
    start_time: string
    end_time: string
    duration_minutes: number
    status: string
    status_display: string
    meeting_link?: string
    meeting_id?: string
    meeting_password?: string
    custom_answers: Record<string, any>
    cancelled_at?: string
    cancellation_reason?: string
    access_token_expires_at: string
    can_cancel: boolean
    can_reschedule: boolean
    attendees?: Attendee[]
    available_spots?: number
  }> =>
    apiClient.get(`/events/booking/${accessToken}/manage/`),

  cancelBookingByToken: (accessToken: string, reason?: string): Promise<{ message: string }> =>
    apiClient.post(`/events/booking/${accessToken}/manage/`, {
      action: 'cancel',
      reason,
    }),

  rescheduleBookingByToken: (accessToken: string, newStartTime: string): Promise<{ message: string }> =>
    apiClient.post(`/events/booking/${accessToken}/manage/`, {
      action: 'reschedule',
      new_start_time: newStartTime,
    }),

  regenerateBookingToken: (accessToken: string): Promise<{
    message: string
    new_token: string
    expires_at: string
  }> =>
    apiClient.post(`/events/booking/${accessToken}/manage/`, {
      action: 'regenerate_token',
    }),

  // Group Event Management
  addAttendeeToBooking: (bookingId: string, data: {
    name: string
    email: string
    phone?: string
    custom_answers?: Record<string, any>
  }): Promise<Attendee> =>
    apiClient.post(`/events/bookings/${bookingId}/attendees/add/`, data),

  removeAttendeeFromBooking: (bookingId: string, attendeeId: string, reason?: string): Promise<{ message: string }> =>
    apiClient.post(`/events/bookings/${bookingId}/attendees/${attendeeId}/remove/`, { reason }),

  // Analytics
  getBookingAnalytics: (days?: number): Promise<BookingAnalytics> => {
    const queryParams = days ? `?days=${days}` : ''
    return apiClient.get(`/events/analytics/${queryParams}`)
  },

  getBookingAuditLogs: (bookingId: string): Promise<{
    booking_id: string
    audit_logs: Array<{
      id: string
      action: string
      action_display: string
      description: string
      actor_type: string
      actor_email?: string
      actor_name?: string
      ip_address?: string
      metadata: Record<string, any>
      old_values: Record<string, any>
      new_values: Record<string, any>
      created_at: string
    }>
    total_logs: number
  }> =>
    apiClient.get(`/events/bookings/${bookingId}/audit/`),

  // Legacy endpoints (for backward compatibility)
  cancelBooking: (bookingId: string, reason?: string): Promise<{ message: string }> =>
    apiClient.post(`/events/bookings/${bookingId}/cancel/`, { reason }),
}

export default eventsService