import { apiClient } from './api'
import type {
  AvailabilityRule,
  AvailabilityRuleRequest,
  DateOverrideRule,
  DateOverrideRequest,
  BlockedTime,
  BlockedTimeRequest,
  RecurringBlockedTime,
  RecurringBlockedTimeRequest,
  BufferTime,
  BufferTimeRequest,
  AvailabilityStats,
  AvailableSlotsResponse,
} from '@/types'

export const availabilityService = {
  // Availability Rules
  getAvailabilityRules: (): Promise<AvailabilityRule[]> =>
    apiClient.get('/availability/rules/'),

  getAvailabilityRule: (id: string): Promise<AvailabilityRule> =>
    apiClient.get(`/availability/rules/${id}/`),

  createAvailabilityRule: (data: AvailabilityRuleRequest): Promise<AvailabilityRule> =>
    apiClient.post('/availability/rules/', data),

  updateAvailabilityRule: (id: string, data: Partial<AvailabilityRuleRequest>): Promise<AvailabilityRule> =>
    apiClient.patch(`/availability/rules/${id}/`, data),

  deleteAvailabilityRule: (id: string): Promise<void> =>
    apiClient.delete(`/availability/rules/${id}/`),

  // Date Override Rules
  getDateOverrides: (): Promise<DateOverrideRule[]> =>
    apiClient.get('/availability/overrides/'),

  getDateOverride: (id: string): Promise<DateOverrideRule> =>
    apiClient.get(`/availability/overrides/${id}/`),

  createDateOverride: (data: DateOverrideRequest): Promise<DateOverrideRule> =>
    apiClient.post('/availability/overrides/', data),

  updateDateOverride: (id: string, data: Partial<DateOverrideRequest>): Promise<DateOverrideRule> =>
    apiClient.patch(`/availability/overrides/${id}/`, data),

  deleteDateOverride: (id: string): Promise<void> =>
    apiClient.delete(`/availability/overrides/${id}/`),

  // Recurring Blocked Times
  getRecurringBlocks: (): Promise<RecurringBlockedTime[]> =>
    apiClient.get('/availability/recurring-blocks/'),

  getRecurringBlock: (id: string): Promise<RecurringBlockedTime> =>
    apiClient.get(`/availability/recurring-blocks/${id}/`),

  createRecurringBlock: (data: RecurringBlockedTimeRequest): Promise<RecurringBlockedTime> =>
    apiClient.post('/availability/recurring-blocks/', data),

  updateRecurringBlock: (id: string, data: Partial<RecurringBlockedTimeRequest>): Promise<RecurringBlockedTime> =>
    apiClient.patch(`/availability/recurring-blocks/${id}/`, data),

  deleteRecurringBlock: (id: string): Promise<void> =>
    apiClient.delete(`/availability/recurring-blocks/${id}/`),

  // Blocked Times
  getBlockedTimes: (): Promise<BlockedTime[]> =>
    apiClient.get('/availability/blocked/'),

  getBlockedTime: (id: string): Promise<BlockedTime> =>
    apiClient.get(`/availability/blocked/${id}/`),

  createBlockedTime: (data: BlockedTimeRequest): Promise<BlockedTime> =>
    apiClient.post('/availability/blocked/', data),

  updateBlockedTime: (id: string, data: Partial<BlockedTimeRequest>): Promise<BlockedTime> =>
    apiClient.patch(`/availability/blocked/${id}/`, data),

  deleteBlockedTime: (id: string): Promise<void> =>
    apiClient.delete(`/availability/blocked/${id}/`),

  // Buffer Time Settings
  getBufferSettings: (): Promise<BufferTime> =>
    apiClient.get('/availability/buffer/'),

  updateBufferSettings: (data: BufferTimeRequest): Promise<BufferTime> =>
    apiClient.patch('/availability/buffer/', data),

  // Calculated Slots (Public endpoint)
  getCalculatedSlots: (
    organizerSlug: string,
    params: {
      event_type_slug: string
      start_date: string
      end_date: string
      invitee_timezone?: string
      attendee_count?: number
      invitee_timezones?: string[]
    }
  ): Promise<AvailableSlotsResponse> => {
    const queryParams = new URLSearchParams()
    queryParams.append('event_type_slug', params.event_type_slug)
    queryParams.append('start_date', params.start_date)
    queryParams.append('end_date', params.end_date)
    if (params.invitee_timezone) queryParams.append('invitee_timezone', params.invitee_timezone)
    if (params.attendee_count) queryParams.append('attendee_count', params.attendee_count.toString())
    if (params.invitee_timezones) {
      queryParams.append('invitee_timezones', params.invitee_timezones.join(','))
    }

    return apiClient.get(`/availability/calculated-slots/${organizerSlug}/?${queryParams.toString()}`)
  },

  // Statistics and Management
  getAvailabilityStats: (): Promise<AvailabilityStats> =>
    apiClient.get('/availability/stats/'),

  clearAvailabilityCache: (): Promise<{ message: string }> =>
    apiClient.post('/availability/cache/clear/'),

  precomputeAvailabilityCache: (daysAhead?: number): Promise<{ message: string }> =>
    apiClient.post('/availability/cache/precompute/', { days_ahead: daysAhead }),

  // Testing and Debugging
  testTimezoneHandling: (timezone?: string, date?: string): Promise<{
    organizer_timezone: string
    test_timezone: string
    test_date: string
    offset_hours: number
    timezone_valid: boolean
    is_dst: boolean
    dst_offset_hours: number
    is_dst_transition_date: boolean
  }> => {
    const queryParams = new URLSearchParams()
    if (timezone) queryParams.append('timezone', timezone)
    if (date) queryParams.append('date', date)

    const queryString = queryParams.toString()
    return apiClient.get(`/availability/test/timezone/${queryString ? `?${queryString}` : ''}`)
  },
}

export default availabilityService