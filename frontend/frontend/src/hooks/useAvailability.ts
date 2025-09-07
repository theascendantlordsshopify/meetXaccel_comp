import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { availabilityService } from '@/services/availability'
import { useUI } from '@/stores/uiStore'
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
} from '@/types'

export function useAvailability() {
  const queryClient = useQueryClient()
  const { showSuccess, showError } = useUI()

  // Availability Rules
  const {
    data: availabilityRules,
    isLoading: rulesLoading,
    error: rulesError,
  } = useQuery({
    queryKey: ['availabilityRules'],
    queryFn: () => availabilityService.getAvailabilityRules(),
  })

  const createRuleMutation = useMutation({
    mutationFn: (data: AvailabilityRuleRequest) => availabilityService.createAvailabilityRule(data),
    onSuccess: () => {
      showSuccess('Availability rule created', 'Your availability rule has been created.')
      queryClient.invalidateQueries({ queryKey: ['availabilityRules'] })
    },
    onError: (error: any) => {
      showError('Failed to create rule', error.message)
    },
  })

  const updateRuleMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<AvailabilityRuleRequest> }) =>
      availabilityService.updateAvailabilityRule(id, data),
    onSuccess: () => {
      showSuccess('Availability rule updated', 'Your availability rule has been updated.')
      queryClient.invalidateQueries({ queryKey: ['availabilityRules'] })
    },
    onError: (error: any) => {
      showError('Failed to update rule', error.message)
    },
  })

  const deleteRuleMutation = useMutation({
    mutationFn: (id: string) => availabilityService.deleteAvailabilityRule(id),
    onSuccess: () => {
      showSuccess('Availability rule deleted', 'The availability rule has been deleted.')
      queryClient.invalidateQueries({ queryKey: ['availabilityRules'] })
    },
    onError: (error: any) => {
      showError('Failed to delete rule', error.message)
    },
  })

  // Date Overrides
  const {
    data: dateOverrides,
    isLoading: overridesLoading,
    error: overridesError,
  } = useQuery({
    queryKey: ['dateOverrides'],
    queryFn: () => availabilityService.getDateOverrides(),
  })

  const createOverrideMutation = useMutation({
    mutationFn: (data: DateOverrideRequest) => availabilityService.createDateOverride(data),
    onSuccess: () => {
      showSuccess('Date override created', 'Your date override has been created.')
      queryClient.invalidateQueries({ queryKey: ['dateOverrides'] })
    },
    onError: (error: any) => {
      showError('Failed to create override', error.message)
    },
  })

  const updateOverrideMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<DateOverrideRequest> }) =>
      availabilityService.updateDateOverride(id, data),
    onSuccess: () => {
      showSuccess('Date override updated', 'Your date override has been updated.')
      queryClient.invalidateQueries({ queryKey: ['dateOverrides'] })
    },
    onError: (error: any) => {
      showError('Failed to update override', error.message)
    },
  })

  const deleteOverrideMutation = useMutation({
    mutationFn: (id: string) => availabilityService.deleteDateOverride(id),
    onSuccess: () => {
      showSuccess('Date override deleted', 'The date override has been deleted.')
      queryClient.invalidateQueries({ queryKey: ['dateOverrides'] })
    },
    onError: (error: any) => {
      showError('Failed to delete override', error.message)
    },
  })

  // Blocked Times
  const {
    data: blockedTimes,
    isLoading: blockedTimesLoading,
    error: blockedTimesError,
  } = useQuery({
    queryKey: ['blockedTimes'],
    queryFn: () => availabilityService.getBlockedTimes(),
  })

  const createBlockedTimeMutation = useMutation({
    mutationFn: (data: BlockedTimeRequest) => availabilityService.createBlockedTime(data),
    onSuccess: () => {
      showSuccess('Blocked time created', 'Your blocked time has been created.')
      queryClient.invalidateQueries({ queryKey: ['blockedTimes'] })
    },
    onError: (error: any) => {
      showError('Failed to create blocked time', error.message)
    },
  })

  const updateBlockedTimeMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<BlockedTimeRequest> }) =>
      availabilityService.updateBlockedTime(id, data),
    onSuccess: () => {
      showSuccess('Blocked time updated', 'Your blocked time has been updated.')
      queryClient.invalidateQueries({ queryKey: ['blockedTimes'] })
    },
    onError: (error: any) => {
      showError('Failed to update blocked time', error.message)
    },
  })

  const deleteBlockedTimeMutation = useMutation({
    mutationFn: (id: string) => availabilityService.deleteBlockedTime(id),
    onSuccess: () => {
      showSuccess('Blocked time deleted', 'The blocked time has been deleted.')
      queryClient.invalidateQueries({ queryKey: ['blockedTimes'] })
    },
    onError: (error: any) => {
      showError('Failed to delete blocked time', error.message)
    },
  })

  // Recurring Blocked Times
  const {
    data: recurringBlocks,
    isLoading: recurringBlocksLoading,
    error: recurringBlocksError,
  } = useQuery({
    queryKey: ['recurringBlocks'],
    queryFn: () => availabilityService.getRecurringBlocks(),
  })

  const createRecurringBlockMutation = useMutation({
    mutationFn: (data: RecurringBlockedTimeRequest) => availabilityService.createRecurringBlock(data),
    onSuccess: () => {
      showSuccess('Recurring block created', 'Your recurring block has been created.')
      queryClient.invalidateQueries({ queryKey: ['recurringBlocks'] })
    },
    onError: (error: any) => {
      showError('Failed to create recurring block', error.message)
    },
  })

  const updateRecurringBlockMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<RecurringBlockedTimeRequest> }) =>
      availabilityService.updateRecurringBlock(id, data),
    onSuccess: () => {
      showSuccess('Recurring block updated', 'Your recurring block has been updated.')
      queryClient.invalidateQueries({ queryKey: ['recurringBlocks'] })
    },
    onError: (error: any) => {
      showError('Failed to update recurring block', error.message)
    },
  })

  const deleteRecurringBlockMutation = useMutation({
    mutationFn: (id: string) => availabilityService.deleteRecurringBlock(id),
    onSuccess: () => {
      showSuccess('Recurring block deleted', 'The recurring block has been deleted.')
      queryClient.invalidateQueries({ queryKey: ['recurringBlocks'] })
    },
    onError: (error: any) => {
      showError('Failed to delete recurring block', error.message)
    },
  })

  // Buffer Settings
  const {
    data: bufferSettings,
    isLoading: bufferSettingsLoading,
    error: bufferSettingsError,
  } = useQuery({
    queryKey: ['bufferSettings'],
    queryFn: () => availabilityService.getBufferSettings(),
  })

  const updateBufferSettingsMutation = useMutation({
    mutationFn: (data: BufferTimeRequest) => availabilityService.updateBufferSettings(data),
    onSuccess: () => {
      showSuccess('Buffer settings updated', 'Your buffer settings have been updated.')
      queryClient.invalidateQueries({ queryKey: ['bufferSettings'] })
    },
    onError: (error: any) => {
      showError('Failed to update buffer settings', error.message)
    },
  })

  // Statistics
  const {
    data: availabilityStats,
    isLoading: statsLoading,
    error: statsError,
  } = useQuery({
    queryKey: ['availabilityStats'],
    queryFn: () => availabilityService.getAvailabilityStats(),
  })

  // Cache Management
  const clearCacheMutation = useMutation({
    mutationFn: () => availabilityService.clearAvailabilityCache(),
    onSuccess: () => {
      showSuccess('Cache cleared', 'Availability cache has been cleared.')
    },
    onError: (error: any) => {
      showError('Failed to clear cache', error.message)
    },
  })

  const precomputeCacheMutation = useMutation({
    mutationFn: (daysAhead?: number) => availabilityService.precomputeAvailabilityCache(daysAhead),
    onSuccess: () => {
      showSuccess('Cache precomputation started', 'Availability cache is being precomputed.')
    },
    onError: (error: any) => {
      showError('Failed to precompute cache', error.message)
    },
  })

  return {
    // Availability Rules
    availabilityRules,
    rulesLoading,
    rulesError,
    createRule: createRuleMutation.mutate,
    updateRule: updateRuleMutation.mutate,
    deleteRule: deleteRuleMutation.mutate,
    isRuleActionLoading:
      createRuleMutation.isPending ||
      updateRuleMutation.isPending ||
      deleteRuleMutation.isPending,

    // Date Overrides
    dateOverrides,
    overridesLoading,
    overridesError,
    createOverride: createOverrideMutation.mutate,
    updateOverride: updateOverrideMutation.mutate,
    deleteOverride: deleteOverrideMutation.mutate,
    isOverrideActionLoading:
      createOverrideMutation.isPending ||
      updateOverrideMutation.isPending ||
      deleteOverrideMutation.isPending,

    // Blocked Times
    blockedTimes,
    blockedTimesLoading,
    blockedTimesError,
    createBlockedTime: createBlockedTimeMutation.mutate,
    updateBlockedTime: updateBlockedTimeMutation.mutate,
    deleteBlockedTime: deleteBlockedTimeMutation.mutate,
    isBlockedTimeActionLoading:
      createBlockedTimeMutation.isPending ||
      updateBlockedTimeMutation.isPending ||
      deleteBlockedTimeMutation.isPending,

    // Recurring Blocks
    recurringBlocks,
    recurringBlocksLoading,
    recurringBlocksError,
    createRecurringBlock: createRecurringBlockMutation.mutate,
    updateRecurringBlock: updateRecurringBlockMutation.mutate,
    deleteRecurringBlock: deleteRecurringBlockMutation.mutate,
    isRecurringBlockActionLoading:
      createRecurringBlockMutation.isPending ||
      updateRecurringBlockMutation.isPending ||
      deleteRecurringBlockMutation.isPending,

    // Buffer Settings
    bufferSettings,
    bufferSettingsLoading,
    bufferSettingsError,
    updateBufferSettings: updateBufferSettingsMutation.mutate,
    isBufferSettingsLoading: updateBufferSettingsMutation.isPending,

    // Statistics
    availabilityStats,
    statsLoading,
    statsError,

    // Cache Management
    clearCache: clearCacheMutation.mutate,
    precomputeCache: precomputeCacheMutation.mutate,
    isCacheActionLoading: clearCacheMutation.isPending || precomputeCacheMutation.isPending,
  }
}