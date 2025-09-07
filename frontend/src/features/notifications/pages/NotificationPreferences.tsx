import React from 'react'
import { Bell, Mail, MessageSquare, Clock, Moon, Calendar, Shield, Save } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { TimePicker } from '@/components/shared/TimePicker'
import { useNotifications } from '@/hooks/useNotifications'
import { ROUTES } from '@/constants/routes'
import { notificationPreferenceSchema, type NotificationPreferenceFormData } from '@/types/forms'

const notificationMethodOptions = [
  { value: 'email', label: 'Email Only' },
  { value: 'sms', label: 'SMS Only' },
  { value: 'both', label: 'Both Email and SMS' },
]

const reminderTimeOptions = [
  { value: 15, label: '15 minutes before' },
  { value: 30, label: '30 minutes before' },
  { value: 60, label: '1 hour before' },
  { value: 120, label: '2 hours before' },
  { value: 240, label: '4 hours before' },
  { value: 1440, label: '1 day before' },
]

export default function NotificationPreferences() {
  const {
    notificationPreferences,
    preferencesLoading,
    updateNotificationPreferences,
    isNotificationActionLoading,
  } = useNotifications()

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors, isDirty },
  } = useForm<NotificationPreferenceFormData>({
    resolver: zodResolver(notificationPreferenceSchema),
  })

  // Reset form when preferences load
  React.useEffect(() => {
    if (notificationPreferences) {
      reset({
        booking_confirmations_email: notificationPreferences.booking_confirmations_email,
        booking_reminders_email: notificationPreferences.booking_reminders_email,
        booking_cancellations_email: notificationPreferences.booking_cancellations_email,
        daily_agenda_email: notificationPreferences.daily_agenda_email,
        booking_confirmations_sms: notificationPreferences.booking_confirmations_sms,
        booking_reminders_sms: notificationPreferences.booking_reminders_sms,
        booking_cancellations_sms: notificationPreferences.booking_cancellations_sms,
        reminder_minutes_before: notificationPreferences.reminder_minutes_before,
        daily_agenda_time: notificationPreferences.daily_agenda_time,
        dnd_enabled: notificationPreferences.dnd_enabled,
        dnd_start_time: notificationPreferences.dnd_start_time,
        dnd_end_time: notificationPreferences.dnd_end_time,
        exclude_weekends_reminders: notificationPreferences.exclude_weekends_reminders,
        exclude_weekends_agenda: notificationPreferences.exclude_weekends_agenda,
        preferred_notification_method: notificationPreferences.preferred_notification_method,
        max_reminders_per_day: notificationPreferences.max_reminders_per_day,
      })
    }
  }, [notificationPreferences, reset])

  const watchedValues = watch()

  const onSubmit = (data: NotificationPreferenceFormData) => {
    updateNotificationPreferences(data)
  }

  if (preferencesLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Notification Preferences"
        subtitle="Configure how and when you receive notifications"
        breadcrumbs={[
          { label: 'Notifications', href: ROUTES.NOTIFICATIONS },
          { label: 'Preferences', current: true },
        ]}
      />

      <Container>
        <div className="max-w-4xl mx-auto">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-8">
            {/* Email Preferences */}
            <Card>
              <CardHeader
                title="Email Notifications"
                subtitle="Configure which email notifications you want to receive"
              />
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Checkbox
                    {...register('booking_confirmations_email')}
                    label="Booking Confirmations"
                    description="Receive email when bookings are confirmed"
                  />

                  <Checkbox
                    {...register('booking_reminders_email')}
                    label="Booking Reminders"
                    description="Receive email reminders before meetings"
                  />

                  <Checkbox
                    {...register('booking_cancellations_email')}
                    label="Booking Cancellations"
                    description="Receive email when bookings are cancelled"
                  />

                  <Checkbox
                    {...register('daily_agenda_email')}
                    label="Daily Agenda"
                    description="Receive daily agenda email each morning"
                  />
                </div>
              </CardContent>
            </Card>

            {/* SMS Preferences */}
            <Card>
              <CardHeader
                title="SMS Notifications"
                subtitle="Configure SMS notifications for important updates"
              />
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Checkbox
                    {...register('booking_confirmations_sms')}
                    label="Booking Confirmations"
                    description="Receive SMS when bookings are confirmed"
                  />

                  <Checkbox
                    {...register('booking_reminders_sms')}
                    label="Booking Reminders"
                    description="Receive SMS reminders before meetings"
                  />

                  <Checkbox
                    {...register('booking_cancellations_sms')}
                    label="Booking Cancellations"
                    description="Receive SMS when bookings are cancelled"
                  />
                </div>

                <div className="bg-info-50 border border-info-200 rounded-lg p-4">
                  <h4 className="font-medium text-info-800 mb-2">SMS Requirements</h4>
                  <p className="text-sm text-info-700">
                    SMS notifications require a verified phone number in your profile. 
                    Standard messaging rates may apply.
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Timing Preferences */}
            <Card>
              <CardHeader
                title="Timing Preferences"
                subtitle="Configure when notifications are sent"
              />
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Select
                    options={reminderTimeOptions}
                    value={watchedValues.reminder_minutes_before}
                    onChange={(value) => register('reminder_minutes_before').onChange({ target: { value } })}
                    label="Reminder Timing"
                    error={errors.reminder_minutes_before?.message}
                    required
                  />

                  <TimePicker
                    value={watchedValues.daily_agenda_time}
                    onChange={(time) => register('daily_agenda_time').onChange({ target: { value: time } })}
                    label="Daily Agenda Time"
                    error={errors.daily_agenda_time?.message}
                    format="24h"
                  />
                </div>

                <Input
                  {...register('max_reminders_per_day', { valueAsNumber: true })}
                  type="number"
                  label="Max Reminders Per Day"
                  min={1}
                  max={50}
                  error={errors.max_reminders_per_day?.message}
                  helpText="Maximum number of reminder notifications per day"
                />
              </CardContent>
            </Card>

            {/* Do Not Disturb */}
            <Card>
              <CardHeader
                title="Do Not Disturb"
                subtitle="Set quiet hours when notifications should not be sent"
              />
              <CardContent className="space-y-6">
                <Checkbox
                  {...register('dnd_enabled')}
                  label="Enable Do Not Disturb"
                  description="Delay notifications during specified hours"
                />

                {watchedValues.dnd_enabled && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <TimePicker
                      value={watchedValues.dnd_start_time}
                      onChange={(time) => register('dnd_start_time').onChange({ target: { value: time } })}
                      label="DND Start Time"
                      error={errors.dnd_start_time?.message}
                      format="24h"
                    />

                    <TimePicker
                      value={watchedValues.dnd_end_time}
                      onChange={(time) => register('dnd_end_time').onChange({ target: { value: time } })}
                      label="DND End Time"
                      error={errors.dnd_end_time?.message}
                      format="24h"
                    />
                  </div>
                )}

                <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <Moon className="h-4 w-4 text-warning-600" />
                    <h4 className="font-medium text-warning-800">How DND Works</h4>
                  </div>
                  <p className="text-sm text-warning-700">
                    Notifications scheduled during DND hours will be delayed until the end of the DND period. 
                    Urgent notifications may still be sent immediately.
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Weekend Preferences */}
            <Card>
              <CardHeader
                title="Weekend Preferences"
                subtitle="Configure weekend notification behavior"
              />
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Checkbox
                    {...register('exclude_weekends_reminders')}
                    label="No Weekend Reminders"
                    description="Don't send booking reminders on weekends"
                  />

                  <Checkbox
                    {...register('exclude_weekends_agenda')}
                    label="No Weekend Agenda"
                    description="Don't send daily agenda emails on weekends"
                  />
                </div>
              </CardContent>
            </Card>

            {/* Communication Method */}
            <Card>
              <CardHeader
                title="Communication Method"
                subtitle="Choose your preferred notification method"
              />
              <CardContent className="space-y-6">
                <Select
                  options={notificationMethodOptions}
                  value={watchedValues.preferred_notification_method}
                  onChange={(value) => register('preferred_notification_method').onChange({ target: { value } })}
                  label="Preferred Method"
                  error={errors.preferred_notification_method?.message}
                />

                <div className="bg-info-50 border border-info-200 rounded-lg p-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <Shield className="h-4 w-4 text-info-600" />
                    <h4 className="font-medium text-info-800">Privacy & Security</h4>
                  </div>
                  <ul className="text-sm text-info-700 space-y-1 list-disc list-inside">
                    <li>Your notification preferences are private and secure</li>
                    <li>You can change these settings at any time</li>
                    <li>Critical notifications may override some preferences</li>
                    <li>SMS notifications require a verified phone number</li>
                  </ul>
                </div>
              </CardContent>
            </Card>

            {/* Form Actions */}
            <div className="flex items-center justify-end space-x-3 pt-6 border-t border-secondary-200">
              <Button
                type="button"
                variant="outline"
                onClick={() => window.location.href = ROUTES.NOTIFICATIONS}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                loading={isNotificationActionLoading}
                disabled={isNotificationActionLoading || !isDirty}
                leftIcon={<Save className="h-4 w-4" />}
              >
                Save Preferences
              </Button>
            </div>
          </form>
        </div>
      </Container>
    </div>
  )
}