import { apiClient } from './api'
import type {
  NotificationTemplate,
  NotificationLog,
  NotificationPreference,
  NotificationSchedule,
  NotificationTemplateRequest,
  NotificationPreferenceRequest,
  NotificationListParams,
  NotificationStats,
  PaginatedResponse,
} from '@/types'

export const notificationsService = {
  // Notification Templates
  getNotificationTemplates: (): Promise<NotificationTemplate[]> =>
    apiClient.get('/notifications/templates/'),

  getNotificationTemplate: (id: string): Promise<NotificationTemplate> =>
    apiClient.get(`/notifications/templates/${id}/`),

  createNotificationTemplate: (data: NotificationTemplateRequest): Promise<NotificationTemplate> =>
    apiClient.post('/notifications/templates/', data),

  updateNotificationTemplate: (id: string, data: Partial<NotificationTemplateRequest>): Promise<NotificationTemplate> =>
    apiClient.patch(`/notifications/templates/${id}/`, data),

  deleteNotificationTemplate: (id: string): Promise<void> =>
    apiClient.delete(`/notifications/templates/${id}/`),

  testNotificationTemplate: (id: string): Promise<{ message: string }> =>
    apiClient.post(`/notifications/templates/${id}/test/`),

  // Notification Logs
  getNotificationLogs: (params?: NotificationListParams): Promise<PaginatedResponse<NotificationLog>> => {
    const queryParams = new URLSearchParams()
    if (params?.status) queryParams.append('status', params.status)
    if (params?.notification_type) queryParams.append('notification_type', params.notification_type)
    if (params?.search) queryParams.append('search', params.search)
    if (params?.start_date) queryParams.append('start_date', params.start_date)
    if (params?.end_date) queryParams.append('end_date', params.end_date)
    if (params?.page) queryParams.append('page', params.page.toString())
    if (params?.page_size) queryParams.append('page_size', params.page_size.toString())

    const queryString = queryParams.toString()
    return apiClient.get(`/notifications/logs/${queryString ? `?${queryString}` : ''}`)
  },

  resendNotification: (id: string): Promise<{ message: string }> =>
    apiClient.post(`/notifications/${id}/resend/`),

  // Notification Preferences
  getNotificationPreferences: (): Promise<NotificationPreference> =>
    apiClient.get('/notifications/preferences/'),

  updateNotificationPreferences: (data: NotificationPreferenceRequest): Promise<NotificationPreference> =>
    apiClient.patch('/notifications/preferences/', data),

  // Scheduled Notifications
  getScheduledNotifications: (): Promise<NotificationSchedule[]> =>
    apiClient.get('/notifications/scheduled/'),

  cancelScheduledNotification: (id: string): Promise<{ message: string }> =>
    apiClient.post(`/notifications/scheduled/${id}/cancel/`),

  // Send Notification
  sendNotification: (data: {
    notification_type: string
    template_id?: string
    recipient_email?: string
    recipient_phone?: string
    subject?: string
    message: string
    booking_id?: string
    send_immediately?: boolean
    scheduled_for?: string
  }): Promise<{ message: string; notification_id: string }> =>
    apiClient.post('/notifications/send/', data),

  // Statistics
  getNotificationStats: (): Promise<NotificationStats> =>
    apiClient.get('/notifications/stats/'),

  // Health
  getNotificationHealth: (): Promise<{
    overall_health: string
    recent_notifications: number
    recent_failures: number
    failure_rate: number
    email_configured: boolean
    sms_configured: boolean
    recent_failure_details?: any[]
  }> =>
    apiClient.get('/notifications/health/'),

  // Export
  exportNotificationLogs: (): Promise<Blob> =>
    apiClient.get('/notifications/export/', {
      responseType: 'blob',
    }),
}

export default notificationsService