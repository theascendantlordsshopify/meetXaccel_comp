import React, { useState } from 'react'
import { useParams } from 'react-router-dom'
import { Calendar, Clock, Users, MapPin, Edit, X, RefreshCw, ExternalLink, Check, AlertTriangle } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { Modal } from '@/components/ui/Modal'
import { Textarea } from '@/components/ui/Textarea'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { Avatar } from '@/components/shared/Avatar'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { eventsService } from '@/services/events'
import { useToggle } from '@/hooks/useToggle'
import { formatDate, formatTime, formatRelativeTime } from '@/utils/date'
import { formatEventDuration, formatLocationType } from '@/utils/format'

export default function BookingManagement() {
  const { accessToken } = useParams<{ accessToken: string }>()
  const queryClient = useQueryClient()
  
  const [cancellationReason, setCancellationReason] = useState('')
  const [showCancelDialog, { toggle: toggleCancelDialog }] = useToggle()
  const [showRescheduleModal, { toggle: toggleRescheduleModal }] = useToggle()
  const [showTokenModal, { toggle: toggleTokenModal }] = useToggle()
  const [actionSuccess, setActionSuccess] = useState<string | null>(null)

  // Get booking data
  const { data: booking, isLoading, error, refetch } = useQuery({
    queryKey: ['bookingManagement', accessToken],
    queryFn: () => eventsService.getBookingByToken(accessToken!),
    enabled: !!accessToken,
    retry: false,
  })

  // Cancel booking mutation
  const cancelMutation = useMutation({
    mutationFn: (reason: string) => eventsService.cancelBookingByToken(accessToken!, reason),
    onSuccess: () => {
      setActionSuccess('Booking cancelled successfully')
      queryClient.invalidateQueries({ queryKey: ['bookingManagement', accessToken] })
      toggleCancelDialog()
    },
    onError: (error: any) => {
      console.error('Failed to cancel booking:', error)
    },
  })

  // Regenerate token mutation
  const regenerateTokenMutation = useMutation({
    mutationFn: () => eventsService.regenerateBookingToken(accessToken!),
    onSuccess: (data) => {
      setActionSuccess('New access link generated')
      // Update URL with new token
      window.history.replaceState({}, '', `/booking/${data.new_token}/manage`)
      queryClient.invalidateQueries({ queryKey: ['bookingManagement'] })
      toggleTokenModal()
    },
    onError: (error: any) => {
      console.error('Failed to regenerate token:', error)
    },
  })

  const handleCancelBooking = () => {
    cancelMutation.mutate(cancellationReason)
  }

  const handleRegenerateToken = () => {
    regenerateTokenMutation.mutate()
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="text-center">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-secondary-600">Loading booking details...</p>
        </div>
      </div>
    )
  }

  if (error || !booking) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="text-center max-w-md">
          <div className="w-16 h-16 bg-error-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <AlertTriangle className="h-8 w-8 text-error-600" />
          </div>
          <h1 className="text-2xl font-bold text-secondary-900 mb-2">
            Booking Not Found
          </h1>
          <p className="text-secondary-600 mb-6">
            The booking link is invalid or has expired. Please contact the organizer for assistance.
          </p>
          <Button onClick={() => window.location.href = '/'}>
            Go to Homepage
          </Button>
        </div>
      </div>
    )
  }

  if (actionSuccess) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="max-w-md w-full">
          <Card className="text-center">
            <CardContent className="p-8">
              <div className="w-16 h-16 bg-success-100 rounded-full flex items-center justify-center mx-auto mb-6">
                <Check className="h-8 w-8 text-success-600" />
              </div>
              
              <h1 className="text-2xl font-bold text-secondary-900 mb-4">
                {actionSuccess}
              </h1>
              
              <p className="text-secondary-600 mb-6">
                Your request has been processed successfully.
              </p>
              
              <Button
                onClick={() => window.location.reload()}
                fullWidth
              >
                Continue
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-secondary-100">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-secondary-900 mb-2">
            Manage Your Booking
          </h1>
          <p className="text-secondary-600">
            View and manage your scheduled meeting
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Booking Details */}
          <div className="lg:col-span-2 space-y-6">
            {/* Booking Overview */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-secondary-900">
                    Booking Details
                  </h2>
                  <StatusBadge status={booking.status} />
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-start space-x-4">
                  <Avatar name={booking.organizer_name} size="lg" />
                  <div className="flex-1">
                    <h3 className="text-xl font-semibold text-secondary-900 mb-1">
                      {booking.event_type_name}
                    </h3>
                    <p className="text-secondary-600 mb-4">
                      with {booking.organizer_name}
                    </p>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="flex items-center space-x-3">
                        <Calendar className="h-5 w-5 text-primary-600" />
                        <div>
                          <p className="text-sm font-medium text-secondary-900">Date</p>
                          <p className="text-sm text-secondary-600">
                            {formatDate(booking.start_time, 'EEEE, MMMM dd, yyyy')}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center space-x-3">
                        <Clock className="h-5 w-5 text-primary-600" />
                        <div>
                          <p className="text-sm font-medium text-secondary-900">Time</p>
                          <p className="text-sm text-secondary-600">
                            {formatTime(booking.start_time)} - {formatTime(booking.end_time)}
                          </p>
                          <p className="text-xs text-secondary-500">
                            {booking.invitee_timezone}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center space-x-3">
                        <Users className="h-5 w-5 text-primary-600" />
                        <div>
                          <p className="text-sm font-medium text-secondary-900">Duration</p>
                          <p className="text-sm text-secondary-600">
                            {booking.duration_minutes} minutes
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center space-x-3">
                        <MapPin className="h-5 w-5 text-primary-600" />
                        <div>
                          <p className="text-sm font-medium text-secondary-900">Location</p>
                          <p className="text-sm text-secondary-600">
                            Video call
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {booking.meeting_link && (
                  <div className="bg-primary-50 p-4 rounded-lg">
                    <h4 className="font-medium text-primary-900 mb-2">Meeting Link</h4>
                    <div className="flex items-center space-x-2">
                      <code className="flex-1 text-sm bg-white px-3 py-2 rounded border">
                        {booking.meeting_link}
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => window.open(booking.meeting_link, '_blank')}
                      >
                        <ExternalLink className="h-4 w-4" />
                      </Button>
                    </div>
                    {booking.meeting_password && (
                      <p className="text-sm text-primary-700 mt-2">
                        Password: <code className="bg-white px-2 py-1 rounded">{booking.meeting_password}</code>
                      </p>
                    )}
                  </div>
                )}

                {booking.custom_answers && Object.keys(booking.custom_answers).length > 0 && (
                  <div>
                    <h4 className="font-medium text-secondary-900 mb-3">Your Responses</h4>
                    <div className="space-y-3">
                      {Object.entries(booking.custom_answers).map(([question, answer]) => (
                        <div key={question} className="bg-secondary-50 p-3 rounded-lg">
                          <p className="text-sm font-medium text-secondary-900">{question}</p>
                          <p className="text-sm text-secondary-600 mt-1">{String(answer)}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Attendees (for group events) */}
            {booking.attendees && booking.attendees.length > 0 && (
              <Card>
                <CardHeader>
                  <h3 className="text-lg font-semibold text-secondary-900">
                    Attendees ({booking.attendees.length})
                  </h3>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {booking.attendees.map((attendee) => (
                      <div key={attendee.id} className="flex items-center justify-between p-3 bg-secondary-50 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <Avatar name={attendee.name} size="sm" />
                          <div>
                            <p className="text-sm font-medium text-secondary-900">{attendee.name}</p>
                            <p className="text-xs text-secondary-500">{attendee.email}</p>
                          </div>
                        </div>
                        <StatusBadge status={attendee.status} />
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <h3 className="text-lg font-semibold text-secondary-900">
                  Quick Actions
                </h3>
              </CardHeader>
              <CardContent className="space-y-3">
                {booking.meeting_link && (
                  <Button
                    variant="primary"
                    fullWidth
                    onClick={() => window.open(booking.meeting_link, '_blank')}
                    leftIcon={<ExternalLink className="h-4 w-4" />}
                  >
                    Join Meeting
                  </Button>
                )}

                {booking.can_reschedule && (
                  <Button
                    variant="outline"
                    fullWidth
                    onClick={toggleRescheduleModal}
                    leftIcon={<Edit className="h-4 w-4" />}
                  >
                    Reschedule
                  </Button>
                )}

                {booking.can_cancel && (
                  <Button
                    variant="outline"
                    fullWidth
                    onClick={toggleCancelDialog}
                    className="text-error-600 hover:text-error-700 border-error-300 hover:border-error-400"
                    leftIcon={<X className="h-4 w-4" />}
                  >
                    Cancel Booking
                  </Button>
                )}

                <Button
                  variant="ghost"
                  fullWidth
                  onClick={toggleTokenModal}
                  leftIcon={<RefreshCw className="h-4 w-4" />}
                >
                  Get New Link
                </Button>
              </CardContent>
            </Card>

            {/* Booking Information */}
            <Card>
              <CardHeader>
                <h3 className="text-lg font-semibold text-secondary-900">
                  Booking Info
                </h3>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-sm font-medium text-secondary-900">Invitee</p>
                  <p className="text-sm text-secondary-600">{booking.invitee_name}</p>
                  <p className="text-xs text-secondary-500">{booking.invitee_email}</p>
                </div>

                {booking.invitee_phone && (
                  <div>
                    <p className="text-sm font-medium text-secondary-900">Phone</p>
                    <p className="text-sm text-secondary-600">{booking.invitee_phone}</p>
                  </div>
                )}

                <div>
                  <p className="text-sm font-medium text-secondary-900">Timezone</p>
                  <p className="text-sm text-secondary-600">{booking.invitee_timezone}</p>
                </div>

                {booking.available_spots !== undefined && (
                  <div>
                    <p className="text-sm font-medium text-secondary-900">Available Spots</p>
                    <p className="text-sm text-secondary-600">
                      {booking.available_spots} remaining
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Access Information */}
            <Card>
              <CardHeader>
                <h3 className="text-lg font-semibold text-secondary-900">
                  Access Information
                </h3>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-sm font-medium text-secondary-900">Link Expires</p>
                  <p className="text-sm text-secondary-600">
                    {formatRelativeTime(booking.access_token_expires_at)}
                  </p>
                </div>

                <div className="bg-info-50 border border-info-200 rounded-lg p-3">
                  <p className="text-xs text-info-700">
                    Keep this link private. Anyone with this link can manage your booking.
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Cancellation Info */}
            {booking.cancelled_at && (
              <Card>
                <CardHeader>
                  <h3 className="text-lg font-semibold text-secondary-900">
                    Cancellation Details
                  </h3>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <p className="text-sm font-medium text-secondary-900">Cancelled</p>
                    <p className="text-sm text-secondary-600">
                      {formatRelativeTime(booking.cancelled_at)}
                    </p>
                  </div>

                  {booking.cancellation_reason && (
                    <div>
                      <p className="text-sm font-medium text-secondary-900">Reason</p>
                      <p className="text-sm text-secondary-600">
                        {booking.cancellation_reason}
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="mt-16 text-center">
          <p className="text-sm text-secondary-500">
            Powered by Calendly Clone
          </p>
        </div>
      </div>

      {/* Cancel Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showCancelDialog}
        onClose={toggleCancelDialog}
        onConfirm={handleCancelBooking}
        title="Cancel Booking"
        message="Are you sure you want to cancel this booking? This action cannot be undone."
        confirmText="Cancel Booking"
        variant="danger"
      >
        <div className="mt-4">
          <Textarea
            label="Reason for cancellation (optional)"
            value={cancellationReason}
            onChange={(e) => setCancellationReason(e.target.value)}
            placeholder="Let the organizer know why you're cancelling..."
            rows={3}
          />
        </div>
      </ConfirmDialog>

      {/* Reschedule Modal */}
      <Modal
        isOpen={showRescheduleModal}
        onClose={toggleRescheduleModal}
        title="Reschedule Booking"
        size="md"
      >
        <div className="space-y-6">
          <div className="text-center">
            <Calendar className="h-12 w-12 text-primary-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              Reschedule Your Meeting
            </h3>
            <p className="text-secondary-600">
              To reschedule your meeting, please contact the organizer directly or book a new time.
            </p>
          </div>

          <div className="bg-info-50 border border-info-200 rounded-lg p-4">
            <h4 className="font-medium text-info-800 mb-2">Contact Information</h4>
            <p className="text-sm text-info-700">
              Organizer: {booking.organizer_name}
            </p>
          </div>

          <div className="flex space-x-3">
            <Button variant="outline" onClick={toggleRescheduleModal} className="flex-1">
              Close
            </Button>
            <Button
              onClick={() => window.location.href = `/${booking.organizer_name.toLowerCase().replace(' ', '-')}`}
              className="flex-1"
            >
              Book New Time
            </Button>
          </div>
        </div>
      </Modal>

      {/* Regenerate Token Modal */}
      <Modal
        isOpen={showTokenModal}
        onClose={toggleTokenModal}
        title="Generate New Access Link"
        size="md"
      >
        <div className="space-y-6">
          <div className="text-center">
            <RefreshCw className="h-12 w-12 text-primary-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              Generate New Access Link
            </h3>
            <p className="text-secondary-600">
              This will create a new secure link for managing your booking. The current link will no longer work.
            </p>
          </div>

          <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
            <h4 className="font-medium text-warning-800 mb-2">Important</h4>
            <ul className="text-sm text-warning-700 space-y-1 list-disc list-inside">
              <li>Your current link will become invalid</li>
              <li>You'll need to save the new link</li>
              <li>The new link will expire in 30 days</li>
            </ul>
          </div>

          <div className="flex space-x-3">
            <Button variant="outline" onClick={toggleTokenModal} className="flex-1">
              Cancel
            </Button>
            <Button
              onClick={handleRegenerateToken}
              loading={regenerateTokenMutation.isPending}
              disabled={regenerateTokenMutation.isPending}
              className="flex-1"
            >
              Generate New Link
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}