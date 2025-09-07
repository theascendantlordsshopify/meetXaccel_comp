import React from 'react'
import { Calendar, Users, Clock, TrendingUp, Plus, ArrowRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { Avatar } from '@/components/shared/Avatar'
import { useAuth } from '@/hooks/useAuth'
import { useEvents } from '@/hooks/useEvents'
import { ROUTES } from '@/constants/routes'
import { formatDate, formatTime } from '@/utils/date'
import { formatNumber } from '@/utils/helpers'

export default function Dashboard() {
  const { user, displayName } = useAuth()
  const { eventTypes, eventTypesLoading, useBookings } = useEvents()
  
  // Get recent bookings
  const { data: bookingsData, isLoading: bookingsLoading } = useBookings({
    page_size: 5,
  })

  const recentBookings = bookingsData?.results || []

  // Mock dashboard stats - in production, these would come from a dedicated API
  const stats = {
    totalBookings: 142,
    upcomingBookings: 8,
    totalEventTypes: eventTypes?.length || 0,
    activeEventTypes: eventTypes?.filter(et => et.is_active).length || 0,
  }

  const quickActions = [
    {
      title: 'Create Event Type',
      description: 'Set up a new meeting type',
      href: ROUTES.EVENT_CREATE,
      icon: <Calendar className="h-6 w-6" />,
      color: 'bg-primary-500',
    },
    {
      title: 'View Bookings',
      description: 'See all your scheduled meetings',
      href: ROUTES.BOOKINGS,
      icon: <Users className="h-6 w-6" />,
      color: 'bg-success-500',
    },
    {
      title: 'Set Availability',
      description: 'Update your available hours',
      href: ROUTES.AVAILABILITY,
      icon: <Clock className="h-6 w-6" />,
      color: 'bg-warning-500',
    },
    {
      title: 'View Analytics',
      description: 'Check your booking insights',
      href: ROUTES.BOOKING_ANALYTICS,
      icon: <TrendingUp className="h-6 w-6" />,
      color: 'bg-secondary-500',
    },
  ]

  return (
    <div className="space-y-8">
      <PageHeader
        title={`Welcome back, ${displayName}!`}
        subtitle="Here's what's happening with your schedule"
      />

      <Container>
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-secondary-600">Total Bookings</p>
                  <p className="text-2xl font-bold text-secondary-900">
                    {formatNumber(stats.totalBookings)}
                  </p>
                </div>
                <div className="p-3 bg-primary-100 rounded-lg">
                  <Calendar className="h-6 w-6 text-primary-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-secondary-600">Upcoming</p>
                  <p className="text-2xl font-bold text-secondary-900">
                    {formatNumber(stats.upcomingBookings)}
                  </p>
                </div>
                <div className="p-3 bg-success-100 rounded-lg">
                  <Clock className="h-6 w-6 text-success-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-secondary-600">Event Types</p>
                  <p className="text-2xl font-bold text-secondary-900">
                    {formatNumber(stats.totalEventTypes)}
                  </p>
                </div>
                <div className="p-3 bg-warning-100 rounded-lg">
                  <Users className="h-6 w-6 text-warning-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-secondary-600">Active Types</p>
                  <p className="text-2xl font-bold text-secondary-900">
                    {formatNumber(stats.activeEventTypes)}
                  </p>
                </div>
                <div className="p-3 bg-secondary-100 rounded-lg">
                  <TrendingUp className="h-6 w-6 text-secondary-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Quick Actions */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader title="Quick Actions" />
              <CardContent>
                <div className="space-y-3">
                  {quickActions.map((action, index) => (
                    <Link key={index} to={action.href}>
                      <div className="flex items-center p-3 rounded-lg border border-secondary-200 hover:border-primary-300 hover:bg-primary-50 transition-colors group">
                        <div className={`p-2 rounded-lg ${action.color} text-white mr-3`}>
                          {action.icon}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-secondary-900 group-hover:text-primary-900">
                            {action.title}
                          </p>
                          <p className="text-xs text-secondary-600">
                            {action.description}
                          </p>
                        </div>
                        <ArrowRight className="h-4 w-4 text-secondary-400 group-hover:text-primary-600" />
                      </div>
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Recent Bookings */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader
                title="Recent Bookings"
                action={
                  <Link to={ROUTES.BOOKINGS}>
                    <Button variant="outline" size="sm">
                      View All
                    </Button>
                  </Link>
                }
              />
              <CardContent>
                {bookingsLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <LoadingSpinner size="lg" />
                  </div>
                ) : recentBookings.length === 0 ? (
                  <div className="text-center py-8">
                    <Calendar className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
                    <p className="text-secondary-600 mb-4">No bookings yet</p>
                    <Link to={ROUTES.EVENT_CREATE}>
                      <Button leftIcon={<Plus className="h-4 w-4" />}>
                        Create your first event type
                      </Button>
                    </Link>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {recentBookings.map((booking) => (
                      <div
                        key={booking.id}
                        className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg hover:border-secondary-300 transition-colors"
                      >
                        <div className="flex items-center space-x-4">
                          <Avatar
                            name={booking.invitee_name}
                            size="md"
                          />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-secondary-900">
                              {booking.invitee_name}
                            </p>
                            <p className="text-sm text-secondary-600">
                              {booking.event_type.name}
                            </p>
                            <p className="text-xs text-secondary-500">
                              {formatDate(booking.start_time)} at {formatTime(booking.start_time)}
                            </p>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-3">
                          <StatusBadge status={booking.status} />
                          <Link to={`${ROUTES.BOOKINGS}/${booking.id}`}>
                            <Button variant="ghost" size="sm">
                              View
                            </Button>
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Event Types Overview */}
        {eventTypes && eventTypes.length > 0 && (
          <Card className="mt-8">
            <CardHeader
              title="Your Event Types"
              action={
                <Link to={ROUTES.EVENTS}>
                  <Button variant="outline" size="sm">
                    Manage All
                  </Button>
                </Link>
              }
            />
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {eventTypes.slice(0, 6).map((eventType) => (
                  <div
                    key={eventType.id}
                    className="p-4 border border-secondary-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 transition-colors"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-medium text-secondary-900">
                        {eventType.name}
                      </h4>
                      <Badge
                        variant={eventType.is_active ? 'success' : 'secondary'}
                        size="sm"
                      >
                        {eventType.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                    <p className="text-sm text-secondary-600 mb-3">
                      {eventType.duration} min • {eventType.max_attendees} {eventType.max_attendees === 1 ? 'person' : 'people'}
                    </p>
                    <div className="flex space-x-2">
                      <Link to={`${ROUTES.EVENTS}/${eventType.id}/edit`}>
                        <Button variant="outline" size="sm" className="flex-1">
                          Edit
                        </Button>
                      </Link>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          // Copy booking link
                          const bookingUrl = `${window.location.origin}/${user?.profile?.organizer_slug}/${eventType.event_type_slug}`
                          navigator.clipboard.writeText(bookingUrl)
                        }}
                      >
                        Copy Link
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </Container>
    </div>
  )
}