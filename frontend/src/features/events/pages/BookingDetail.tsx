import React from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Calendar, Clock, Users, MapPin, Phone, Mail, ExternalLink, Edit, MessageSquare } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { Avatar } from '@/components/shared/Avatar'
import { eventsService } from '@/services/events'
import { ROUTES } from '@/constants/routes'
import { formatDate, formatTime, formatRelativeTime } from '@/utils/date'
import { formatLocationType } from '@/utils/format'

export default function BookingDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const { data: booking, isLoading, error } = useQuery({
    queryKey: ['booking', id],
    queryFn: () => eventsService.getBooking(id!),
    enabled: !!id,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (error || !booking) {
    return (
      <div className="text-center py-12">
        <p className="text-error-600">Booking not found</p>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Booking Details"
        subtitle={`Meeting with ${booking.invitee_name}`}
        breadcrumbs={[
          { label: 'Bookings', href: ROUTES.BOOKINGS },
          { label: booking.invitee_name, current: true },
        ]}
        action={
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.open(`/booking/${booking.access_token}/manage`, '_blank')}
              leftIcon={<ExternalLink className="h-4 w-4" />}
            >
              Invitee View
            </Button>
          </div>
        }
      />

      <Container>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Details */}
          <div className="lg:col-span-2 space-y-6">
            {/* Booking Overview */}
            <Card>
              <CardHeader
                title="Booking Information"
                action={<StatusBadge status={booking.status} />}
              />
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
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
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    <Users className="h-5 w-5 text-primary-600" />
                    <div>
                      <p className="text-sm font-medium text-secondary-900">Attendees</p>
                      <p className="text-sm text-secondary-600">
                        {booking.attendee_count} {booking.attendee_count === 1 ? 'person' : 'people'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    <MapPin className="h-5 w-5 text-primary-600" />
                    <div>
                      <p className="text-sm font-medium text-secondary-900">Location</p>
                      <p className="text-sm text-secondary-600">
                        {formatLocationType(booking.event_type.location_type)}
                      </p>
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
                    <h4 className="font-medium text-secondary-900 mb-3">Custom Answers</h4>
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
                <CardHeader title="Attendees" />
                <CardContent>
                  <div className="space-y-4">
                    {booking.attendees.map((attendee) => (
                      <div key={attendee.id} className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <Avatar name={attendee.name} size="sm" />
                          <div>
                            <p className="text-sm font-medium text-secondary-900">{attendee.name}</p>
                            <p className="text-xs text-secondary-500">{attendee.email}</p>
                            {attendee.phone && (
                              <p className="text-xs text-secondary-500">{attendee.phone}</p>
                            )}
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
            {/* Invitee Information */}
            <Card>
              <CardHeader title="Invitee" />
              <CardContent>
                <div className="flex items-center space-x-3 mb-4">
                  <Avatar name={booking.invitee_name} size="md" />
                  <div>
                    <p className="font-medium text-secondary-900">{booking.invitee_name}</p>
                    <p className="text-sm text-secondary-600">{booking.invitee_timezone}</p>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center space-x-2">
                    <Mail className="h-4 w-4 text-secondary-400" />
                    <a
                      href={`mailto:${booking.invitee_email}`}
                      className="text-sm text-primary-600 hover:text-primary-700"
                    >
                      {booking.invitee_email}
                    </a>
                  </div>

                  {booking.invitee_phone && (
                    <div className="flex items-center space-x-2">
                      <Phone className="h-4 w-4 text-secondary-400" />
                      <a
                        href={`tel:${booking.invitee_phone}`}
                        className="text-sm text-primary-600 hover:text-primary-700"
                      >
                        {booking.invitee_phone}
                      </a>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Event Type Info */}
            <Card>
              <CardHeader title="Event Type" />
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <p className="font-medium text-secondary-900">{booking.event_type.name}</p>
                    {booking.event_type.description && (
                      <p className="text-sm text-secondary-600 mt-1">
                        {booking.event_type.description}
                      </p>
                    )}
                  </div>

                  <div className="flex items-center space-x-4 text-sm text-secondary-600">
                    <div className="flex items-center space-x-1">
                      <Clock className="h-4 w-4" />
                      <span>{booking.duration_minutes} min</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Users className="h-4 w-4" />
                      <span>Max {booking.event_type.max_attendees}</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Booking Timeline */}
            <Card>
              <CardHeader title="Timeline" />
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-start space-x-3">
                    <div className="w-2 h-2 bg-success-500 rounded-full mt-2"></div>
                    <div>
                      <p className="text-sm font-medium text-secondary-900">Booking Created</p>
                      <p className="text-xs text-secondary-500">
                        {formatRelativeTime(booking.created_at)}
                      </p>
                    </div>
                  </div>

                  {booking.cancelled_at && (
                    <div className="flex items-start space-x-3">
                      <div className="w-2 h-2 bg-error-500 rounded-full mt-2"></div>
                      <div>
                        <p className="text-sm font-medium text-secondary-900">Cancelled</p>
                        <p className="text-xs text-secondary-500">
                          {formatRelativeTime(booking.cancelled_at)}
                        </p>
                        {booking.cancellation_reason && (
                          <p className="text-xs text-secondary-600 mt-1">
                            Reason: {booking.cancellation_reason}
                          </p>
                        )}
                      </div>
                    </div>
                  )}

                  {booking.rescheduled_at && (
                    <div className="flex items-start space-x-3">
                      <div className="w-2 h-2 bg-warning-500 rounded-full mt-2"></div>
                      <div>
                        <p className="text-sm font-medium text-secondary-900">Rescheduled</p>
                        <p className="text-xs text-secondary-500">
                          {formatRelativeTime(booking.rescheduled_at)}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card>
              <CardHeader title="Actions" />
              <CardContent>
                <div className="space-y-3">
                  <Button
                    variant="outline"
                    size="sm"
                    fullWidth
                    leftIcon={<MessageSquare className="h-4 w-4" />}
                  >
                    Send Message
                  </Button>

                  <Button
                    variant="outline"
                    size="sm"
                    fullWidth
                    leftIcon={<Edit className="h-4 w-4" />}
                  >
                    Edit Booking
                  </Button>

                  {booking.can_cancel && (
                    <Button
                      variant="outline"
                      size="sm"
                      fullWidth
                      className="text-error-600 hover:text-error-700"
                    >
                      Cancel Booking
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </Container>
    </div>
  )
}