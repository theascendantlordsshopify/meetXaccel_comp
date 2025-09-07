import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { eventsService } from '@/services/events'
import { useUI } from '@/stores/uiStore'
import type {
  EventType,
  CreateEventTypeRequest,
  Booking,
  CreateBookingRequest,
  BookingListParams,
  AvailableSlotsParams,
} from '@/types'

export function useEvents() {
  const queryClient = useQueryClient()
  const { showSuccess, showError } = useUI()

  // Event Types
  const {
    data: eventTypes,
    isLoading: eventTypesLoading,
    error: eventTypesError,
  } = useQuery({
    queryKey: ['eventTypes'],
    queryFn: () => eventsService.getEventTypes(),
  })

  const createEventTypeMutation = useMutation({
    mutationFn: (data: CreateEventTypeRequest) => eventsService.createEventType(data),
    onSuccess: () => {
      showSuccess('Event type created', 'Your new event type has been created successfully.')
      queryClient.invalidateQueries({ queryKey: ['eventTypes'] })
    },
    onError: (error: any) => {
      showError('Failed to create event type', error.message)
    },
  })

  const updateEventTypeMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CreateEventTypeRequest> }) =>
      eventsService.updateEventType(id, data),
    onSuccess: () => {
      showSuccess('Event type updated', 'Your event type has been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['eventTypes'] })
    },
    onError: (error: any) => {
      showError('Failed to update event type', error.message)
    },
  })

  const deleteEventTypeMutation = useMutation({
    mutationFn: (id: string) => eventsService.deleteEventType(id),
    onSuccess: () => {
      showSuccess('Event type deleted', 'The event type has been deleted successfully.')
      queryClient.invalidateQueries({ queryKey: ['eventTypes'] })
    },
    onError: (error: any) => {
      showError('Failed to delete event type', error.message)
    },
  })

  // Bookings
  const useBookings = (params?: BookingListParams) => {
    return useQuery({
      queryKey: ['bookings', params],
      queryFn: () => eventsService.getBookings(params),
    })
  }

  const useBooking = (id: string) => {
    return useQuery({
      queryKey: ['booking', id],
      queryFn: () => eventsService.getBooking(id),
      enabled: !!id,
    })
  }

  const createBookingMutation = useMutation({
    mutationFn: (data: CreateBookingRequest) => eventsService.createBooking(data),
    onSuccess: () => {
      showSuccess('Booking created', 'Your booking has been confirmed!')
      queryClient.invalidateQueries({ queryKey: ['bookings'] })
    },
    onError: (error: any) => {
      showError('Booking failed', error.message)
    },
  })

  const updateBookingMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) =>
      eventsService.updateBooking(id, data),
    onSuccess: () => {
      showSuccess('Booking updated', 'The booking has been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['bookings'] })
    },
    onError: (error: any) => {
      showError('Failed to update booking', error.message)
    },
  })

  const cancelBookingMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason?: string }) =>
      eventsService.cancelBooking(id, reason),
    onSuccess: () => {
      showSuccess('Booking cancelled', 'The booking has been cancelled successfully.')
      queryClient.invalidateQueries({ queryKey: ['bookings'] })
    },
    onError: (error: any) => {
      showError('Failed to cancel booking', error.message)
    },
  })

  // Available Slots
  const useAvailableSlots = (
    organizerSlug: string,
    eventTypeSlug: string,
    params: AvailableSlotsParams
  ) => {
    return useQuery({
      queryKey: ['availableSlots', organizerSlug, eventTypeSlug, params],
      queryFn: () => eventsService.getAvailableSlots(organizerSlug, eventTypeSlug, params),
      enabled: !!(organizerSlug && eventTypeSlug && params.start_date && params.end_date),
      staleTime: 5 * 60 * 1000, // 5 minutes
    })
  }

  // Public Pages
  const usePublicOrganizerPage = (organizerSlug: string) => {
    return useQuery({
      queryKey: ['publicOrganizer', organizerSlug],
      queryFn: () => eventsService.getPublicOrganizerPage(organizerSlug),
      enabled: !!organizerSlug,
      staleTime: 15 * 60 * 1000, // 15 minutes
    })
  }

  const usePublicEventTypePage = (
    organizerSlug: string,
    eventTypeSlug: string,
    params?: {
      start_date?: string
      end_date?: string
      timezone?: string
      attendee_count?: number
    }
  ) => {
    return useQuery({
      queryKey: ['publicEventType', organizerSlug, eventTypeSlug, params],
      queryFn: () => eventsService.getPublicEventTypePage(organizerSlug, eventTypeSlug, params),
      enabled: !!(organizerSlug && eventTypeSlug),
      staleTime: 5 * 60 * 1000, // 5 minutes
    })
  }

  // Analytics
  const useBookingAnalytics = (days?: number) => {
    return useQuery({
      queryKey: ['bookingAnalytics', days],
      queryFn: () => eventsService.getBookingAnalytics(days),
    })
  }

  return {
    // Event Types
    eventTypes,
    eventTypesLoading,
    eventTypesError,
    createEventType: createEventTypeMutation.mutate,
    updateEventType: updateEventTypeMutation.mutate,
    deleteEventType: deleteEventTypeMutation.mutate,
    isEventTypeActionLoading: 
      createEventTypeMutation.isPending || 
      updateEventTypeMutation.isPending || 
      deleteEventTypeMutation.isPending,

    // Bookings
    useBookings,
    useBooking,
    createBooking: createBookingMutation.mutate,
    updateBooking: updateBookingMutation.mutate,
    cancelBooking: cancelBookingMutation.mutate,
    isBookingActionLoading:
      createBookingMutation.isPending ||
      updateBookingMutation.isPending ||
      cancelBookingMutation.isPending,

    // Available Slots
    useAvailableSlots,

    // Public Pages
    usePublicOrganizerPage,
    usePublicEventTypePage,

    // Analytics
    useBookingAnalytics,
  }
}