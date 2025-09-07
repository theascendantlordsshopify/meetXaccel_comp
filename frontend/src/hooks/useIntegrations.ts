import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { integrationsService } from '@/services/integrations'
import { useUI } from '@/stores/uiStore'
import type {
  CalendarIntegration,
  VideoConferenceIntegration,
  WebhookIntegration,
  WebhookIntegrationRequest,
  IntegrationHealth,
} from '@/types'

export function useIntegrations() {
  const queryClient = useQueryClient()
  const { showSuccess, showError } = useUI()

  // Calendar Integrations
  const {
    data: calendarIntegrations,
    isLoading: calendarIntegrationsLoading,
    error: calendarIntegrationsError,
  } = useQuery({
    queryKey: ['calendarIntegrations'],
    queryFn: () => integrationsService.getCalendarIntegrations(),
  })

  // Video Integrations
  const {
    data: videoIntegrations,
    isLoading: videoIntegrationsLoading,
    error: videoIntegrationsError,
  } = useQuery({
    queryKey: ['videoIntegrations'],
    queryFn: () => integrationsService.getVideoIntegrations(),
  })

  // Webhook Integrations
  const {
    data: webhookIntegrations,
    isLoading: webhookIntegrationsLoading,
    error: webhookIntegrationsError,
  } = useQuery({
    queryKey: ['webhookIntegrations'],
    queryFn: () => integrationsService.getWebhookIntegrations(),
  })

  // Integration Health
  const {
    data: integrationHealth,
    isLoading: healthLoading,
    error: healthError,
    refetch: refreshHealth,
  } = useQuery({
    queryKey: ['integrationHealth'],
    queryFn: () => integrationsService.getIntegrationHealth(),
    refetchInterval: 5 * 60 * 1000, // Refresh every 5 minutes
  })

  // OAuth Initiation
  const initiateOAuthMutation = useMutation({
    mutationFn: (data: {
      provider: string
      integration_type: string
      redirect_uri: string
    }) => integrationsService.initiateOAuth(data),
    onError: (error: any) => {
      showError('OAuth initiation failed', error.message)
    },
  })

  // Calendar Integration Actions
  const refreshCalendarSyncMutation = useMutation({
    mutationFn: (integrationId: string) => integrationsService.refreshCalendarSync(integrationId),
    onSuccess: () => {
      showSuccess('Calendar sync initiated', 'Your calendar is being synced in the background.')
      queryClient.invalidateQueries({ queryKey: ['calendarIntegrations'] })
    },
    onError: (error: any) => {
      showError('Failed to refresh calendar sync', error.message)
    },
  })

  const deleteCalendarIntegrationMutation = useMutation({
    mutationFn: (integrationId: string) => integrationsService.deleteCalendarIntegration(integrationId),
    onSuccess: () => {
      showSuccess('Calendar integration deleted', 'The calendar integration has been removed.')
      queryClient.invalidateQueries({ queryKey: ['calendarIntegrations'] })
      queryClient.invalidateQueries({ queryKey: ['integrationHealth'] })
    },
    onError: (error: any) => {
      showError('Failed to delete calendar integration', error.message)
    },
  })

  // Video Integration Actions
  const deleteVideoIntegrationMutation = useMutation({
    mutationFn: (integrationId: string) => integrationsService.deleteVideoIntegration(integrationId),
    onSuccess: () => {
      showSuccess('Video integration deleted', 'The video integration has been removed.')
      queryClient.invalidateQueries({ queryKey: ['videoIntegrations'] })
      queryClient.invalidateQueries({ queryKey: ['integrationHealth'] })
    },
    onError: (error: any) => {
      showError('Failed to delete video integration', error.message)
    },
  })

  // Webhook Integration Actions
  const createWebhookIntegrationMutation = useMutation({
    mutationFn: (data: WebhookIntegrationRequest) => integrationsService.createWebhookIntegration(data),
    onSuccess: () => {
      showSuccess('Webhook created', 'Your webhook integration has been created successfully.')
      queryClient.invalidateQueries({ queryKey: ['webhookIntegrations'] })
    },
    onError: (error: any) => {
      showError('Failed to create webhook', error.message)
    },
  })

  const updateWebhookIntegrationMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<WebhookIntegrationRequest> }) =>
      integrationsService.updateWebhookIntegration(id, data),
    onSuccess: () => {
      showSuccess('Webhook updated', 'Your webhook integration has been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['webhookIntegrations'] })
    },
    onError: (error: any) => {
      showError('Failed to update webhook', error.message)
    },
  })

  const deleteWebhookIntegrationMutation = useMutation({
    mutationFn: (integrationId: string) => integrationsService.deleteWebhookIntegration(integrationId),
    onSuccess: () => {
      showSuccess('Webhook deleted', 'The webhook integration has been removed.')
      queryClient.invalidateQueries({ queryKey: ['webhookIntegrations'] })
    },
    onError: (error: any) => {
      showError('Failed to delete webhook', error.message)
    },
  })

  const testWebhookMutation = useMutation({
    mutationFn: (integrationId: string) => integrationsService.testWebhook(integrationId),
    onSuccess: () => {
      showSuccess('Test webhook sent', 'A test webhook has been sent to your endpoint.')
    },
    onError: (error: any) => {
      showError('Failed to send test webhook', error.message)
    },
  })

  return {
    // Calendar Integrations
    calendarIntegrations,
    calendarIntegrationsLoading,
    calendarIntegrationsError,
    refreshCalendarSync: refreshCalendarSyncMutation.mutate,
    deleteCalendarIntegration: deleteCalendarIntegrationMutation.mutate,

    // Video Integrations
    videoIntegrations,
    videoIntegrationsLoading,
    videoIntegrationsError,
    deleteVideoIntegration: deleteVideoIntegrationMutation.mutate,

    // Webhook Integrations
    webhookIntegrations,
    webhookIntegrationsLoading,
    webhookIntegrationsError,
    createWebhookIntegration: createWebhookIntegrationMutation.mutate,
    updateWebhookIntegration: updateWebhookIntegrationMutation.mutate,
    deleteWebhookIntegration: deleteWebhookIntegrationMutation.mutate,
    testWebhook: testWebhookMutation.mutate,

    // OAuth
    initiateOAuth: initiateOAuthMutation.mutateAsync,

    // Health
    integrationHealth,
    healthLoading,
    healthError,
    refreshHealth,

    // Loading states
    isIntegrationActionLoading:
      refreshCalendarSyncMutation.isPending ||
      deleteCalendarIntegrationMutation.isPending ||
      deleteVideoIntegrationMutation.isPending ||
      createWebhookIntegrationMutation.isPending ||
      updateWebhookIntegrationMutation.isPending ||
      deleteWebhookIntegrationMutation.isPending ||
      testWebhookMutation.isPending ||
      initiateOAuthMutation.isPending,
  }
}