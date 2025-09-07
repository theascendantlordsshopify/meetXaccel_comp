import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Plus, Calendar, Users, Clock, Settings, Copy, Eye, Edit, Trash2, MoreHorizontal } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { Modal } from '@/components/ui/Modal'
import { useEvents } from '@/hooks/useEvents'
import { useAuth } from '@/hooks/useAuth'
import { useToggle } from '@/hooks/useToggle'
import { ROUTES, buildRoute } from '@/constants/routes'
import { formatEventDuration } from '@/utils/format'
import { copyToClipboard } from '@/utils/helpers'
import { cn } from '@/utils/cn'

export default function EventTypes() {
  const { user } = useAuth()
  const { eventTypes, eventTypesLoading, deleteEventType, isEventTypeActionLoading } = useEvents()
  const [selectedEventType, setSelectedEventType] = useState<string | null>(null)
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()
  const [showPreviewModal, { toggle: togglePreviewModal }] = useToggle()

  const handleCopyLink = async (eventType: any) => {
    const bookingUrl = `${window.location.origin}/${user?.profile?.organizer_slug}/${eventType.event_type_slug}`
    const success = await copyToClipboard(bookingUrl)
    if (success) {
      // Toast notification will be shown by the copy function
    }
  }

  const handleDeleteEventType = () => {
    if (selectedEventType) {
      deleteEventType(selectedEventType)
      setSelectedEventType(null)
      toggleDeleteDialog()
    }
  }

  const handlePreviewEventType = (eventType: any) => {
    setSelectedEventType(eventType.id)
    togglePreviewModal()
  }

  const selectedEventTypeData = eventTypes?.find(et => et.id === selectedEventType)

  if (eventTypesLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Event Types"
        subtitle="Manage your meeting types and booking settings"
        action={
          <Link to={ROUTES.EVENT_CREATE}>
            <Button leftIcon={<Plus className="h-4 w-4" />}>
              Create Event Type
            </Button>
          </Link>
        }
      />

      <Container>
        {!eventTypes || eventTypes.length === 0 ? (
          <EmptyState
            icon={<Calendar className="h-12 w-12" />}
            title="No event types yet"
            description="Create your first event type to start accepting bookings"
            action={{
              label: 'Create Event Type',
              onClick: () => window.location.href = ROUTES.EVENT_CREATE,
            }}
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {eventTypes.map((eventType) => (
              <Card
                key={eventType.id}
                className="group hover:shadow-medium transition-all duration-200 border-l-4 border-l-primary-500"
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <h3 className="text-lg font-semibold text-secondary-900 group-hover:text-primary-900 transition-colors">
                        {eventType.name}
                      </h3>
                      <p className="text-sm text-secondary-600 mt-1 line-clamp-2">
                        {eventType.description || 'No description provided'}
                      </p>
                    </div>
                    <div className="flex items-center space-x-1 ml-4">
                      <StatusBadge status={eventType.is_active ? 'active' : 'inactive'} />
                      <div className="relative group/menu">
                        <Button variant="ghost" size="sm">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                        <div className="absolute right-0 top-full mt-1 w-48 bg-white rounded-lg shadow-strong border border-secondary-200 py-1 opacity-0 invisible group-hover/menu:opacity-100 group-hover/menu:visible transition-all duration-200 z-10">
                          <button
                            onClick={() => handlePreviewEventType(eventType)}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <Eye className="h-4 w-4" />
                            <span>Preview</span>
                          </button>
                          <Link
                            to={buildRoute.eventEdit(eventType.id)}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <Edit className="h-4 w-4" />
                            <span>Edit</span>
                          </Link>
                          <button
                            onClick={() => handleCopyLink(eventType)}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <Copy className="h-4 w-4" />
                            <span>Copy Link</span>
                          </button>
                          <hr className="my-1 border-secondary-100" />
                          <button
                            onClick={() => {
                              setSelectedEventType(eventType.id)
                              toggleDeleteDialog()
                            }}
                            className="w-full px-3 py-2 text-left text-sm text-error-600 hover:bg-error-50 flex items-center space-x-2"
                          >
                            <Trash2 className="h-4 w-4" />
                            <span>Delete</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardHeader>

                <CardContent>
                  <div className="space-y-4">
                    {/* Event Details */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="flex items-center space-x-2 text-sm text-secondary-600">
                        <Clock className="h-4 w-4" />
                        <span>{formatEventDuration(eventType.duration)}</span>
                      </div>
                      <div className="flex items-center space-x-2 text-sm text-secondary-600">
                        <Users className="h-4 w-4" />
                        <span>
                          {eventType.max_attendees === 1 
                            ? '1-on-1' 
                            : `Up to ${eventType.max_attendees}`
                          }
                        </span>
                      </div>
                    </div>

                    {/* Location */}
                    <div className="flex items-center space-x-2 text-sm text-secondary-600">
                      <div className="w-4 h-4 rounded-full bg-primary-100 flex items-center justify-center">
                        <div className="w-2 h-2 rounded-full bg-primary-600" />
                      </div>
                      <span className="capitalize">
                        {eventType.location_type.replace('_', ' ')}
                      </span>
                    </div>

                    {/* Booking Settings */}
                    <div className="flex flex-wrap gap-2">
                      {eventType.is_private && (
                        <Badge variant="secondary" size="sm">Private</Badge>
                      )}
                      {eventType.enable_waitlist && (
                        <Badge variant="info" size="sm">Waitlist</Badge>
                      )}
                      {eventType.max_attendees > 1 && (
                        <Badge variant="primary" size="sm">Group Event</Badge>
                      )}
                    </div>

                    {/* Actions */}
                    <div className="flex space-x-2 pt-2 border-t border-secondary-100">
                      <Link to={buildRoute.eventEdit(eventType.id)} className="flex-1">
                        <Button variant="outline" size="sm" fullWidth>
                          <Edit className="h-4 w-4 mr-2" />
                          Edit
                        </Button>
                      </Link>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleCopyLink(eventType)}
                        className="flex-1"
                      >
                        <Copy className="h-4 w-4 mr-2" />
                        Copy Link
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </Container>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        onClose={toggleDeleteDialog}
        onConfirm={handleDeleteEventType}
        title="Delete Event Type"
        message="Are you sure you want to delete this event type? This action cannot be undone and will cancel all future bookings."
        confirmText="Delete"
        variant="danger"
      />

      {/* Preview Modal */}
      <Modal
        isOpen={showPreviewModal}
        onClose={togglePreviewModal}
        title="Event Type Preview"
        size="lg"
      >
        {selectedEventTypeData && (
          <div className="space-y-6">
            <div className="text-center">
              <h3 className="text-2xl font-bold text-secondary-900 mb-2">
                {selectedEventTypeData.name}
              </h3>
              <p className="text-secondary-600">
                {selectedEventTypeData.description || 'No description provided'}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="bg-secondary-50 p-4 rounded-lg">
                <div className="flex items-center space-x-2 mb-2">
                  <Clock className="h-5 w-5 text-primary-600" />
                  <span className="font-medium text-secondary-900">Duration</span>
                </div>
                <p className="text-lg font-semibold text-secondary-900">
                  {formatEventDuration(selectedEventTypeData.duration)}
                </p>
              </div>

              <div className="bg-secondary-50 p-4 rounded-lg">
                <div className="flex items-center space-x-2 mb-2">
                  <Users className="h-5 w-5 text-primary-600" />
                  <span className="font-medium text-secondary-900">Attendees</span>
                </div>
                <p className="text-lg font-semibold text-secondary-900">
                  {selectedEventTypeData.max_attendees === 1 
                    ? '1-on-1 meeting' 
                    : `Up to ${selectedEventTypeData.max_attendees} people`
                  }
                </p>
              </div>
            </div>

            <div className="bg-primary-50 p-4 rounded-lg">
              <h4 className="font-medium text-primary-900 mb-2">Booking Link</h4>
              <div className="flex items-center space-x-2">
                <code className="flex-1 text-sm bg-white px-3 py-2 rounded border">
                  {`${window.location.origin}/${user?.profile?.organizer_slug}/${selectedEventTypeData.event_type_slug}`}
                </code>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleCopyLink(selectedEventTypeData)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex space-x-3">
              <Link to={buildRoute.eventEdit(selectedEventTypeData.id)} className="flex-1">
                <Button variant="primary" fullWidth>
                  <Edit className="h-4 w-4 mr-2" />
                  Edit Event Type
                </Button>
              </Link>
              <Button
                variant="outline"
                onClick={() => window.open(`/${user?.profile?.organizer_slug}/${selectedEventTypeData.event_type_slug}`, '_blank')}
              >
                <Eye className="h-4 w-4 mr-2" />
                View Public Page
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}