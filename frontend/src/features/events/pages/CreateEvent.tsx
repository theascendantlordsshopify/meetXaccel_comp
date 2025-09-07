import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, Calendar, Clock, Users, MapPin, Settings, Plus, Trash2 } from 'lucide-react'
import { useForm, useFieldArray } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { useEvents } from '@/hooks/useEvents'
import { ROUTES } from '@/constants/routes'
import { EVENT_DURATIONS, LOCATION_TYPES, QUESTION_TYPES } from '@/constants'
import { eventTypeSchema, type EventTypeFormData } from '@/types/forms'

export default function CreateEvent() {
  const navigate = useNavigate()
  const { createEventType, isEventTypeActionLoading } = useEvents()

  const {
    register,
    control,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<EventTypeFormData>({
    resolver: zodResolver(eventTypeSchema),
    defaultValues: {
      duration: 30,
      max_attendees: 1,
      location_type: 'video_call',
      min_scheduling_notice: 60,
      max_scheduling_horizon: 43200,
      buffer_time_before: 0,
      buffer_time_after: 0,
      is_active: true,
      is_private: false,
      enable_waitlist: false,
    },
  })

  const { fields: questions, append: addQuestion, remove: removeQuestion } = useFieldArray({
    control,
    name: 'questions_data',
  })

  const watchedValues = watch()

  const onSubmit = (data: EventTypeFormData) => {
    createEventType(data)
      .then(() => {
        navigate(ROUTES.EVENTS)
      })
      .catch(() => {
        // Error handling is done in the hook
      })
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
        title="Create Event Type"
        subtitle="Set up a new meeting type for your calendar"
        breadcrumbs={[
          { label: 'Event Types', href: ROUTES.EVENTS },
          { label: 'Create', current: true },
        ]}
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
                    placeholder="60"
                    error={errors.min_scheduling_notice?.message}
                    helpText="How far in advance can people book?"
                  />

                  <Input
                    {...register('max_scheduling_horizon', { valueAsNumber: true })}
                    type="number"
                    label="Maximum Advance (minutes)"
                    placeholder="43200"
                    error={errors.max_scheduling_horizon?.message}
                    helpText="How far in advance can people book?"
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Input
                    {...register('buffer_time_before', { valueAsNumber: true })}
                    type="number"
                    label="Buffer Before (minutes)"
                    placeholder="0"
                    error={errors.buffer_time_before?.message}
                    helpText="Time to block before meetings"
                  />

                  <Input
                    {...register('buffer_time_after', { valueAsNumber: true })}
                    type="number"
                    label="Buffer After (minutes)"
                    placeholder="0"
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
                      <Card key={question.id} variant="outlined">
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
                  disabled={isEventTypeActionLoading}
                  leftIcon={<Calendar className="h-4 w-4" />}
                >
                  Create Event Type
                </Button>
              </div>
            </div>
          </form>
        </div>
      </Container>
    </div>
  )
}