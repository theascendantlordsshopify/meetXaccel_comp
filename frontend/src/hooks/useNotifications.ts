import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { notificationsService } from '@/services/notifications'
import { useUI } from '@/stores/uiStore'
import type {
  NotificationTemplate,
  NotificationLog,
  NotificationPreference,
  NotificationSchedule,
  NotificationTemplateRequest,
  NotificationPreferenceRequest,
  NotificationListParams,
  NotificationStats,
} from '@/types'

export function useNotifications() {
  const queryClient = useQueryClient()
  const { showSuccess, showError } = useUI()

  // Notification Templates
  const {
    data: notificationTemplates,
    isLoading: notificationTemplatesLoading,
    error: notificationTemplatesError,
  } = useQuery({
    queryKey: ['notificationTemplates'],
    queryFn: () => notificationsService.getNotificationTemplates(),
  })

  const createNotificationTemplateMutation = useMutation({
    mutationFn: (data: NotificationTemplateRequest) => notificationsService.createNotificationTemplate(data),
    onSuccess: () => {
      showSuccess('Template created', 'Your notification template has been created successfully.')
      queryClient.invalidateQueries({ queryKey: ['notificationTemplates'] })
    },
    onError: (error: any) => {
      showError('Failed to create template', error.message)
    },
  })

  const updateNotificationTemplateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<NotificationTemplateRequest> }) =>
      notificationsService.updateNotificationTemplate(id, data),
    onSuccess: () => {
      showSuccess('Template updated', 'Your notification template has been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['notificationTemplates'] })
    },
    onError: (error: any) => {
      showError('Failed to update template', error.message)
    },
  })

  const deleteNotificationTemplateMutation = useMutation({
    mutationFn: (id: string) => notificationsService.deleteNotificationTemplate(id),
    onSuccess: () => {
      showSuccess('Template deleted', 'The notification template has been deleted successfully.')
      queryClient.invalidateQueries({ queryKey: ['notificationTemplates'] })
    },
    onError: (error: any) => {
      showError('Failed to delete template', error.message)
    },
  })

  const testNotificationTemplateMutation = useMutation({
    mutationFn: (id: string) => notificationsService.testNotificationTemplate(id),
    onSuccess: () => {
      showSuccess('Test notification sent', 'A test notification has been sent to your email.')
    },
    onError: (error: any) => {
      showError('Failed to send test notification', error.message)
    },
  })

  // Notification Logs
  const useNotificationLogs = (params?: NotificationListParams) => {
    return useQuery({
      queryKey: ['notificationLogs', params],
      queryFn: () => notificationsService.getNotificationLogs(params),
    })
  }

  const resendNotificationMutation = useMutation({
    mutationFn: (id: string) => notificationsService.resendNotification(id),
    onSuccess: () => {
      showSuccess('Notification queued', 'The notification has been queued for resending.')
      queryClient.invalidateQueries({ queryKey: ['notificationLogs'] })
    },
    onError: (error: any) => {
      showError('Failed to resend notification', error.message)
    },
  })

  // Notification Preferences
  const {
    data: notificationPreferences,
    isLoading: preferencesLoading,
    error: preferencesError,
  } = useQuery({
    queryKey: ['notificationPreferences'],
    queryFn: () => notificationsService.getNotificationPreferences(),
  })

  const updateNotificationPreferencesMutation = useMutation({
    mutationFn: (data: NotificationPreferenceRequest) => notificationsService.updateNotificationPreferences(data),
    onSuccess: () => {
      showSuccess('Preferences updated', 'Your notification preferences have been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['notificationPreferences'] })
    },
    onError: (error: any) => {
      showError('Failed to update preferences', error.message)
    },
  })

  // Scheduled Notifications
  const {
    data: scheduledNotifications,
    isLoading: scheduledLoading,
    error: scheduledError,
  } = useQuery({
    queryKey: ['scheduledNotifications'],
    queryFn: () => notificationsService.getScheduledNotifications(),
  })

  const cancelScheduledNotificationMutation = useMutation({
    mutationFn: (id: string) => notificationsService.cancelScheduledNotification(id),
    onSuccess: () => {
      showSuccess('Notification cancelled', 'The scheduled notification has been cancelled.')
      queryClient.invalidateQueries({ queryKey: ['scheduledNotifications'] })
    },
    onError: (error: any) => {
      showError('Failed to cancel notification', error.message)
    },
  })

  // Send Notification
  const sendNotificationMutation = useMutation({
    mutationFn: (data: any) => notificationsService.sendNotification(data),
    onSuccess: () => {
      showSuccess('Notification sent', 'Your notification has been sent successfully.')
      queryClient.invalidateQueries({ queryKey: ['notificationLogs'] })
    },
    onError: (error: any) => {
      showError('Failed to send notification', error.message)
    },
  })

  // Statistics
  const useNotificationStats = () => {
    return useQuery({
      queryKey: ['notificationStats'],
      queryFn: () => notificationsService.getNotificationStats(),
    })
  }

  // Export
  const exportNotificationLogsMutation = useMutation({
    mutationFn: () => notificationsService.exportNotificationLogs(),
    onSuccess: () => {
      showSuccess('Export started', 'Your notification logs export will download shortly.')
    },
    onError: (error: any) => {
      showError('Export failed', error.message)
    },
  })

  return {
    // Templates
    notificationTemplates,
    notificationTemplatesLoading,
    notificationTemplatesError,
    createNotificationTemplate: createNotificationTemplateMutation.mutate,
    updateNotificationTemplate: updateNotificationTemplateMutation.mutate,
    deleteNotificationTemplate: deleteNotificationTemplateMutation.mutate,
    testNotificationTemplate: testNotificationTemplateMutation.mutate,

    // Logs
    notificationLogs: useNotificationLogs,
    resendNotification: resendNotificationMutation.mutate,

    // Preferences
    notificationPreferences,
    preferencesLoading,
    preferencesError,
    updateNotificationPreferences: updateNotificationPreferencesMutation.mutate,

    // Scheduled
    scheduledNotifications,
    scheduledLoading,
    scheduledError,
    cancelScheduledNotification: cancelScheduledNotificationMutation.mutate,

    // Send
    sendNotification: sendNotificationMutation.mutate,

    // Statistics
    notificationStats: useNotificationStats,

    // Export
    exportNotificationLogs: exportNotificationLogsMutation.mutate,

    // Loading states
    isNotificationActionLoading:
      createNotificationTemplateMutation.isPending ||
      updateNotificationTemplateMutation.isPending ||
      deleteNotificationTemplateMutation.isPending ||
      testNotificationTemplateMutation.isPending ||
      resendNotificationMutation.isPending ||
      updateNotificationPreferencesMutation.isPending ||
      cancelScheduledNotificationMutation.isPending ||
      sendNotificationMutation.isPending ||
      exportNotificationLogsMutation.isPending,
  }
}