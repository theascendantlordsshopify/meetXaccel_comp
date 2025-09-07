import React, { useState } from 'react'
import { Calendar, Clock, Users, MapPin, ArrowRight } from 'lucide-react'
import { useForm, useFieldArray } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { FormField } from '@/components/forms/FormField'
import { TimePicker } from '@/components/shared/TimePicker'
import { useEvents } from '@/hooks/useEvents'
import { formatDate, formatTime } from '@/utils/date'
import { formatLocationType } from '@/utils/format'
import { COMMON_TIMEZONES } from '@/constants'
import { bookingSchema, type BookingFormData } from '@/types/forms'
import type { EventType, CustomQuestion, AvailableSlot } from '@/types'

interface BookingFormProps {
  eventType: EventType
  selectedSlot: AvailableSlot
  onSuccess?: (booking: any) => void
  onCancel?: () => void
}

export function BookingForm({ eventType, selectedSlot, onSuccess, onCancel }: BookingFormProps) {
  const { createBooking, isBookingActionLoading } = useEvents()
  const [currentStep, setCurrentStep] = useState(1)

  const {
    register,
    control,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<BookingFormData>({
    resolver: zodResolver(bookingSchema),
    defaultValues: {
      invitee_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      attendee_count: 1,
    },
  })

  const { fields: attendees, append: addAttendee, remove: removeAttendee } = useFieldArray({
    control,
    name: 'attendees_data',
  })

  const watchedValues = watch()
  const isGroupEvent = eventType.max_attendees > 1
  const totalSteps = eventType.questions?.length > 0 ? 3 : 2

  const onSubmit = (data: BookingFormData) => {
    const bookingData = {
      ...data,
      organizer_slug: eventType.organizer.profile.organizer_slug,
      event_type_slug: eventType.event_type_slug,
      start_time: selectedSlot.start_time,
    }

    createBooking(bookingData)
      .then((booking) => {
        onSuccess?.(booking)
      })
      .catch(() => {
        // Error handling is done in the hook
      })
  }

  const nextStep = () => {
    setCurrentStep(prev => Math.min(prev + 1, totalSteps))
  }

  const prevStep = () => {
    setCurrentStep(prev => Math.max(prev - 1, 1))
  }

  const addAdditionalAttendee = () => {
    addAttendee({
      name: '',
      email: '',
      phone: '',
      custom_answers: {},
    })
  }

  return (
    <div className="max-w-2xl mx-auto">
      {/* Progress Indicator */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          {Array.from({ length: totalSteps }, (_, i) => i + 1).map((step) => (
            <div key={step} className="flex items-center">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                  step <= currentStep
                    ? 'bg-primary-600 text-white'
                    : 'bg-secondary-200 text-secondary-600'
                }`}
              >
                {step}
              </div>
              {step < totalSteps && (
                <div
                  className={`w-16 h-1 mx-2 ${
                    step < currentStep ? 'bg-primary-600' : 'bg-secondary-200'
                  }`}
                />
              )}
            </div>
          ))}
        </div>
        <div className="flex justify-between mt-2 text-sm text-secondary-600">
          <span>Your Details</span>
          {eventType.questions?.length > 0 && <span>Questions</span>}
          <span>Confirmation</span>
        </div>
      </div>

      <form onSubmit={handleSubmit(onSubmit)}>
        {/* Step 1: Basic Information */}
        {currentStep === 1 && (
          <Card>
            <CardHeader title="Your Information" />
            <CardContent className="space-y-6">
              {/* Selected Time Display */}
              <div className="bg-primary-50 p-4 rounded-lg">
                <div className="flex items-center space-x-3">
                  <Calendar className="h-5 w-5 text-primary-600" />
                  <div>
                    <p className="font-medium text-primary-900">{eventType.name}</p>
                    <p className="text-sm text-primary-700">
                      {formatDate(selectedSlot.start_time)} at {formatTime(selectedSlot.start_time)}
                    </p>
                    <p className="text-xs text-primary-600">
                      {selectedSlot.duration_minutes} minutes • {formatLocationType(eventType.location_type)}
                    </p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Input
                  {...register('invitee_name')}
                  label="Full Name"
                  placeholder="John Doe"
                  error={errors.invitee_name?.message}
                  required
                  autoFocus
                />

                <Input
                  {...register('invitee_email')}
                  type="email"
                  label="Email Address"
                  placeholder="john@example.com"
                  error={errors.invitee_email?.message}
                  required
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Input
                  {...register('invitee_phone')}
                  type="tel"
                  label="Phone Number (optional)"
                  placeholder="+1 (555) 123-4567"
                  error={errors.invitee_phone?.message}
                />

                <Select
                  options={COMMON_TIMEZONES}
                  value={watchedValues.invitee_timezone}
                  onChange={(value) => register('invitee_timezone').onChange({ target: { value } })}
                  label="Timezone"
                  error={errors.invitee_timezone?.message}
                  required
                  searchable
                />
              </div>

              {isGroupEvent && (
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <label className="text-sm font-medium text-secondary-700">
                      Additional Attendees (optional)
                    </label>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={addAdditionalAttendee}
                      disabled={attendees.length >= eventType.max_attendees - 1}
                    >
                      Add Attendee
                    </Button>
                  </div>

                  {attendees.map((attendee, index) => (
                    <Card key={attendee.id} variant="outlined" className="mb-4">
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between mb-4">
                          <h4 className="font-medium text-secondary-900">
                            Attendee {index + 2}
                          </h4>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => removeAttendee(index)}
                          >
                            Remove
                          </Button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <Input
                            {...register(`attendees_data.${index}.name`)}
                            label="Name"
                            placeholder="Jane Smith"
                            error={errors.attendees_data?.[index]?.name?.message}
                            required
                          />

                          <Input
                            {...register(`attendees_data.${index}.email`)}
                            type="email"
                            label="Email"
                            placeholder="jane@example.com"
                            error={errors.attendees_data?.[index]?.email?.message}
                            required
                          />
                        </div>

                        <Input
                          {...register(`attendees_data.${index}.phone`)}
                          type="tel"
                          label="Phone (optional)"
                          placeholder="+1 (555) 123-4567"
                          error={errors.attendees_data?.[index]?.phone?.message}
                          className="mt-4"
                        />
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}

              <div className="flex justify-end">
                <Button type="button" onClick={nextStep}>
                  Next Step
                  <ArrowRight className="h-4 w-4 ml-2" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Step 2: Custom Questions */}
        {currentStep === 2 && eventType.questions?.length > 0 && (
          <Card>
            <CardHeader title="Additional Information" />
            <CardContent className="space-y-6">
              {eventType.questions.map((question, index) => (
                <FormField
                  key={question.id}
                  field={{
                    name: `custom_answers.${question.question_text}`,
                    label: question.question_text,
                    type: question.question_type,
                    required: question.is_required,
                    options: question.options?.map(opt => ({ value: opt, label: opt })) || [],
                  }}
                  value={watchedValues.custom_answers?.[question.question_text]}
                  onChange={(value) => 
                    register(`custom_answers.${question.question_text}`).onChange({ target: { value } })
                  }
                  error={errors.custom_answers?.[question.question_text]?.message}
                />
              ))}

              <div className="flex justify-between">
                <Button type="button" variant="outline" onClick={prevStep}>
                  Previous
                </Button>
                <Button type="button" onClick={nextStep}>
                  Next Step
                  <ArrowRight className="h-4 w-4 ml-2" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Step 3: Confirmation */}
        {currentStep === totalSteps && (
          <Card>
            <CardHeader title="Confirm Your Booking" />
            <CardContent className="space-y-6">
              {/* Booking Summary */}
              <div className="bg-secondary-50 p-6 rounded-lg">
                <h3 className="font-semibold text-secondary-900 mb-4">Booking Summary</h3>
                
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-secondary-600">Event:</span>
                    <span className="font-medium text-secondary-900">{eventType.name}</span>
                  </div>
                  
                  <div className="flex justify-between">
                    <span className="text-secondary-600">Date & Time:</span>
                    <span className="font-medium text-secondary-900">
                      {formatDate(selectedSlot.start_time)} at {formatTime(selectedSlot.start_time)}
                    </span>
                  </div>
                  
                  <div className="flex justify-between">
                    <span className="text-secondary-600">Duration:</span>
                    <span className="font-medium text-secondary-900">{selectedSlot.duration_minutes} minutes</span>
                  </div>
                  
                  <div className="flex justify-between">
                    <span className="text-secondary-600">Location:</span>
                    <span className="font-medium text-secondary-900">
                      {formatLocationType(eventType.location_type)}
                    </span>
                  </div>

                  {isGroupEvent && (
                    <div className="flex justify-between">
                      <span className="text-secondary-600">Attendees:</span>
                      <span className="font-medium text-secondary-900">
                        {(watchedValues.attendees_data?.length || 0) + 1} people
                      </span>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex justify-between">
                <Button type="button" variant="outline" onClick={prevStep}>
                  Previous
                </Button>
                <div className="flex space-x-3">
                  <Button type="button" variant="outline" onClick={onCancel}>
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    loading={isBookingActionLoading}
                    disabled={isBookingActionLoading}
                  >
                    Confirm Booking
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </form>
    </div>
  )
}