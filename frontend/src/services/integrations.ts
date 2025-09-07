import { apiClient } from './api'
import type {
  CalendarIntegration,
  VideoConferenceIntegration,
  WebhookIntegration,
  WebhookIntegrationRequest,
  IntegrationHealth,
  IntegrationLog,
} from '@/types'

export const integrationsService = {
  // Calendar Integrations
  getCalendarIntegrations: (): Promise<CalendarIntegration[]> =>
    apiClient.get('/integrations/calendar/'),

  getCalendarIntegration: (id: string): Promise<CalendarIntegration> =>
    apiClient.get(`/integrations/calendar/${id}/`),

  updateCalendarIntegration: (id: string, data: Partial<CalendarIntegration>): Promise<CalendarIntegration> =>
    apiClient.patch(`/integrations/calendar/${id}/`, data),

  deleteCalendarIntegration: (id: string): Promise<void> =>
    apiClient.delete(`/integrations/calendar/${id}/`),

  refreshCalendarSync: (id: string): Promise<{ message: string }> =>
    apiClient.post(`/integrations/calendar/${id}/refresh/`),

  forceCalendarSync: (id: string): Promise<{ message: string }> =>
    apiClient.post(`/integrations/calendar/${id}/force-sync/`),

  // Video Integrations
  getVideoIntegrations: (): Promise<VideoConferenceIntegration[]> =>
    apiClient.get('/integrations/video/'),

  getVideoIntegration: (id: string): Promise<VideoConferenceIntegration> =>
    apiClient.get(`/integrations/video/${id}/`),

  updateVideoIntegration: (id: string, data: Partial<VideoConferenceIntegration>): Promise<VideoConferenceIntegration> =>
    apiClient.patch(`/integrations/video/${id}/`, data),

  deleteVideoIntegration: (id: string): Promise<void> =>
    apiClient.delete(`/integrations/video/${id}/`),

  // Webhook Integrations
  getWebhookIntegrations: (): Promise<WebhookIntegration[]> =>
    apiClient.get('/integrations/webhooks/'),

  getWebhookIntegration: (id: string): Promise<WebhookIntegration> =>
    apiClient.get(`/integrations/webhooks/${id}/`),

  createWebhookIntegration: (data: WebhookIntegrationRequest): Promise<WebhookIntegration> =>
    apiClient.post('/integrations/webhooks/', data),

  updateWebhookIntegration: (id: string, data: Partial<WebhookIntegrationRequest>): Promise<WebhookIntegration> =>
    apiClient.patch(`/integrations/webhooks/${id}/`, data),

  deleteWebhookIntegration: (id: string): Promise<void> =>
    apiClient.delete(`/integrations/webhooks/${id}/`),

  testWebhook: (id: string): Promise<{ message: string }> =>
    apiClient.post(`/integrations/webhooks/${id}/test/`),

  // Integration Logs
  getIntegrationLogs: (): Promise<IntegrationLog[]> =>
    apiClient.get('/integrations/logs/'),

  // OAuth
  initiateOAuth: (data: {
    provider: string
    integration_type: string
    redirect_uri: string
  }): Promise<{
    authorization_url: string
    provider: string
    integration_type: string
    state: string
  }> =>
    apiClient.post('/integrations/oauth/initiate/', data),

  handleOAuthCallback: (data: {
    provider: string
    integration_type: string
    code: string
    state?: string
  }): Promise<{
    message: string
    provider: string
    integration_type: string
    provider_email?: string
    created: boolean
  }> =>
    apiClient.post('/integrations/oauth/callback/', data),

  // Health and Monitoring
  getIntegrationHealth: (): Promise<IntegrationHealth> =>
    apiClient.get('/integrations/health/'),

  getCalendarConflicts: (): Promise<{
    conflicts: any
    manual_blocks_count: number
    synced_blocks_count: number
  }> =>
    apiClient.get('/integrations/calendar/conflicts/'),
}

export default integrationsService