import React, { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Calendar, Save, Trash2, Eye, Copy } from 'lucide-react'
import { useForm, useFieldArray } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { useEvents } from '@/hooks/useEvents'
import { useAuth } from '@/hooks/useAuth'
import { useToggle } from '@/hooks/useToggle'
import { ROUTES } from '@/constants/routes'
import { EVENT_DURATIONS, LOCATION_TYPES, QUESTION_TYPES } from '@/constants'
import { eventTypeSchema, type EventTypeFormData } from '@/types/forms'
import { copyToClipboard } from '@/utils/helpers'

export default function EditEvent() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const { updateEventType, deleteEventType, isEventTypeActionLoading } = useEvents()
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()

  // Get event type data
  const { data: eventType, isLoading } = useQuery({
    queryKey: ['eventType', id],
    queryFn: () => eventsService.getEventType(id!),
    enabled: !!id,
  })

  const {
    register,
    control,
    handleSubmit,
    watch,
    reset,
    formState: { errors, isDirty },
  } = useForm<EventTypeFormData>({
    resolver: zodResolver(eventTypeSchema),
  })

  const { fields: questions, append: addQuestion, remove: removeQuestion } = useFieldArray({
    control,
    name: 'questions_data',
  })

  // Reset form when event type data loads
  React.useEffect(() => {
    if (eventType) {
      reset({
        name: eventType.name,
        description: eventType.description || '',
        duration: eventType.duration,
        max_attendees: eventType.max_attendees,
        location_type: eventType.location_type,
        location_details: eventType.location_details || '',
        min_scheduling_notice: eventType.min_scheduling_notice,
        max_scheduling_horizon: eventType.max_scheduling_horizon,
        buffer_time_before: eventType.buffer_time_before,
        buffer_time_after: eventType.buffer_time_after,
        max_bookings_per_day: eventType.max_bookings_per_day || undefined,
        is_active: eventType.is_active,
        is_private: eventType.is_private,
        enable_waitlist: eventType.enable_waitlist,
        redirect_url_after_booking: eventType.redirect_url_after_booking || '',
        questions_data: eventType.questions?.map(q => ({
          question_text: q.question_text,
          question_type: q.question_type,
          is_required: q.is_required,
          order: q.order,
          options: q.options || [],
        })) || [],
      })
    }
  }, [eventType, reset])

  const watchedValues = watch()

  const onSubmit = (data: EventTypeFormData) => {
    if (!id) return

    updateEventType({ id, data })
      .then(() => {
        navigate(ROUTES.EVENTS)
      })
      .catch(() => {
        // Error handling is done in the hook
      })
  }

  const handleDelete = () => {
    if (!id) return

    deleteEventType(id)
      .then(() => {
        navigate(ROUTES.EVENTS)
      })
      .catch(() => {
        // Error handling is done in the hook
      })
  }

  const handleCopyLink = async () => {
    if (!eventType || !user) return

    const bookingUrl = `${window.location.origin}/${user.profile?.organizer_slug}/${eventType.event_type_slug}`
    const success = await copyToClipboard(bookingUrl)
    if (success) {
      // Toast notification will be shown by the copy function
    }
  }

  const handlePreview = () => {
    if (!eventType || !user) return

    const bookingUrl = `${window.location.origin}/${user.profile?.organizer_slug}/${eventType.event_type_slug}`
    window.open(bookingUrl, '_blank')
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (!eventType) {
    return (
      <div className="text-center py-12">
        <p className="text-error-600">Event type not found</p>
      </div>
    )
  }

  const durationOptions = EVENT_DURATIONS.map(duration => ({
    value: duration,
    label: duration < 60 ? `${duration} min` : `${duration / 60} hr${duration > 60 ? 's' : ''}`,
  }))

  const addCustomQuestion = () => {
    addQuestion({
      question_text: '',
      question_type: 'text',
      is_required: false,
      order: questions.length,
      options: [],
    })
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title={`Edit: ${eventType.name}`}
        subtitle="Update your event type settings"
        breadcrumbs={[
          { label: 'Event Types', href: ROUTES.EVENTS },
          { label: eventType.name, current: true },
        ]}
        action={
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handlePreview}
              leftIcon={<Eye className="h-4 w-4" />}
            >
              Preview
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleCopyLink}
              leftIcon={<Copy className="h-4 w-4" />}
            >
              Copy Link
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={toggleDeleteDialog}
              leftIcon={<Trash2 className="h-4 w-4" />}
            >
              Delete
            </Button>
          </div>
        }
      />

      <Container>
        <div className="max-w-4xl mx-auto">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-8">
            {/* Basic Information */}
            <Card>
              <CardHeader title="Basic Information" />
              <CardContent className="space-y-6">
                <Input
                  {...register('name')}
                  label="Event Name"
                  placeholder="e.g., Discovery Call, Team Meeting"
                  error={errors.name?.message}
                  required
                />

                <Textarea
                  {...register('description')}
                  label="Description"
                  placeholder="Describe what this meeting is about..."
                  error={errors.description?.message}
                  rows={3}
                />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Select
                    options={durationOptions}
                    value={watchedValues.duration}
                    onChange={(value) => register('duration').onChange({ target: { value } })}
                    label="Duration"
                    error={errors.duration?.message}
                    required
                  />

                  <Input
                    {...register('max_attendees', { valueAsNumber: true })}
                    type="number"
                    label="Maximum Attendees"
                    min={1}
                    max={100}
                    error={errors.max_attendees?.message}
                    required
                  />
                </div>
              </CardContent>
            </Card>

            {/* Location Settings */}
            <Card>
              <CardHeader title="Location" />
              <CardContent className="space-y-6">
                <Select
                  options={LOCATION_TYPES}
                  value={watchedValues.location_type}
                  onChange={(value) => register('location_type').onChange({ target: { value } })}
                  label="Location Type"
                  error={errors.location_type?.message}
                  required
                />

                {watchedValues.location_type === 'in_person' && (
                  <Textarea
                    {...register('location_details')}
                    label="Location Details"
                    placeholder="Enter the meeting address..."
                    error={errors.location_details?.message}
                    rows={2}
                  />
                )}

                {watchedValues.location_type === 'phone_call' && (
                  <Input
                    {...register('location_details')}
                    label="Phone Number"
                    placeholder="Phone number to call"
                    error={errors.location_details?.message}
                  />
                )}

                {watchedValues.location_type === 'custom' && (
                  <Textarea
                    {...register('location_details')}
                    label="Custom Location Instructions"
                    placeholder="Provide custom meeting instructions..."
                    error={errors.location_details?.message}
                    rows={3}
                  />
                )}
              </CardContent>
            </Card>

            {/* Scheduling Settings */}
            <Card>
              <CardHeader title="Scheduling Settings" />
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Input
                    {...register('min_scheduling_notice', { valueAsNumber: true })}
                    type="number"
                    label="Minimum Notice (minutes)"
                    error={errors.min_scheduling_notice?.message}
                    helpText="How far in advance can people book?"
                  />

                  <Input
                    {...register('max_scheduling_horizon', { valueAsNumber: true })}
                    type="number"
                    label="Maximum Advance (minutes)"
                    error={errors.max_scheduling_horizon?.message}
                    helpText="How far in advance can people book?"
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Input
                    {...register('buffer_time_before', { valueAsNumber: true })}
                    type="number"
                    label="Buffer Before (minutes)"
                    error={errors.buffer_time_before?.message}
                    helpText="Time to block before meetings"
                  />

                  <Input
                    {...register('buffer_time_after', { valueAsNumber: true })}
                    type="number"
                    label="Buffer After (minutes)"
                    error={errors.buffer_time_after?.message}
                    helpText="Time to block after meetings"
                  />
                </div>

                <Input
                  {...register('max_bookings_per_day', { valueAsNumber: true })}
                  type="number"
                  label="Max Bookings Per Day (optional)"
                  placeholder="Leave empty for unlimited"
                  error={errors.max_bookings_per_day?.message}
                  helpText="Limit daily bookings for this event type"
                />
              </CardContent>
            </Card>

            {/* Advanced Settings */}
            <Card>
              <CardHeader title="Advanced Settings" />
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <Checkbox
                    {...register('is_active')}
                    label="Active"
                    description="Allow new bookings for this event type"
                  />

                  <Checkbox
                    {...register('is_private')}
                    label="Private"
                    description="Only accessible via direct link"
                  />

                  <Checkbox
                    {...register('enable_waitlist')}
                    label="Enable Waitlist"
                    description="Allow people to join waitlist when fully booked"
                  />
                </div>

                <Input
                  {...register('redirect_url_after_booking')}
                  type="url"
                  label="Redirect URL After Booking (optional)"
                  placeholder="https://example.com/thank-you"
                  error={errors.redirect_url_after_booking?.message}
                  helpText="Where to redirect invitees after successful booking"
                />
              </CardContent>
            </Card>

            {/* Custom Questions */}
            <Card>
              <CardHeader
                title="Custom Questions"
                subtitle="Collect additional information from invitees"
                action={
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={addCustomQuestion}
                    leftIcon={<Plus className="h-4 w-4" />}
                  >
                    Add Question
                  </Button>
                }
              />
              <CardContent>
                {questions.length === 0 ? (
                  <div className="text-center py-8">
                    <p className="text-secondary-500 mb-4">No custom questions added yet</p>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={addCustomQuestion}
                      leftIcon={<Plus className="h-4 w-4" />}
                    >
                      Add Your First Question
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {questions.map((question, index) => (
                      <Card key={question.id || index} variant="outlined">
                        <CardContent className="p-4">
                          <div className="flex items-start justify-between mb-4">
                            <h4 className="font-medium text-secondary-900">
                              Question {index + 1}
                            </h4>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => removeQuestion(index)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>

                          <div className="space-y-4">
                            <Input
                              {...register(`questions_data.${index}.question_text`)}
                              label="Question"
                              placeholder="What's your question?"
                              error={errors.questions_data?.[index]?.question_text?.message}
                              required
                            />

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <Select
                                options={QUESTION_TYPES}
                                value={watchedValues.questions_data?.[index]?.question_type}
                                onChange={(value) => 
                                  register(`questions_data.${index}.question_type`).onChange({ target: { value } })
                                }
                                label="Question Type"
                                error={errors.questions_data?.[index]?.question_type?.message}
                                required
                              />

                              <div className="flex items-center pt-6">
                                <Checkbox
                                  {...register(`questions_data.${index}.is_required`)}
                                  label="Required"
                                />
                              </div>
                            </div>

                            {['select', 'multiselect', 'radio'].includes(
                              watchedValues.questions_data?.[index]?.question_type
                            ) && (
                              <div>
                                <label className="block text-sm font-medium text-secondary-700 mb-2">
                                  Options
                                </label>
                                <Textarea
                                  {...register(`questions_data.${index}.options`)}
                                  placeholder="Enter options, one per line"
                                  rows={3}
                                  helpText="Enter each option on a new line"
                                />
                              </div>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Form Actions */}
            <div className="flex items-center justify-between pt-6 border-t border-secondary-200">
              <Button
                type="button"
                variant="outline"
                onClick={() => navigate(ROUTES.EVENTS)}
                leftIcon={<ArrowLeft className="h-4 w-4" />}
              >
                Back to Event Types
              </Button>

              <div className="flex space-x-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate(ROUTES.EVENTS)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  loading={isEventTypeActionLoading}
                  disabled={isEventTypeActionLoading || !isDirty}
                  leftIcon={<Save className="h-4 w-4" />}
                >
                  Save Changes
                </Button>
              </div>
            </div>
          </form>
        </div>
      </Container>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        onClose={toggleDeleteDialog}
        onConfirm={handleDelete}
        title="Delete Event Type"
        message="Are you sure you want to delete this event type? This action cannot be undone and will cancel all future bookings."
        confirmText="Delete"
        variant="danger"
      />
    </div>
  )
}