import React, { useState } from 'react'
import { Send, Mail, MessageSquare, User, Users, AtSign } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
import { Modal } from '@/components/ui/Modal'
import { useNotifications } from '@/hooks/useNotifications'
import { useEvents } from '@/hooks/useEvents'
import { sendNotificationSchema, type SendNotificationFormData } from '@/types/forms'

interface NotificationComposerProps {
  isOpen: boolean
  onClose: () => void
  prefilledData?: Partial<SendNotificationFormData>
}

const notificationTypeOptions = [
  { value: 'email', label: 'Email', icon: <Mail className="h-4 w-4" /> },
  { value: 'sms', label: 'SMS', icon: <MessageSquare className="h-4 w-4" /> },
]

const recipientTypeOptions = [
  { value: 'manual', label: 'Manual Entry', icon: <User className="h-4 w-4" /> },
  { value: 'booking', label: 'From Booking', icon: <Users className="h-4 w-4" /> },
  { value: 'template', label: 'Use Template', icon: <AtSign className="h-4 w-4" /> },
]

export function NotificationComposer({ isOpen, onClose, prefilledData }: NotificationComposerProps) {
  const [recipientType, setRecipientType] = useState('manual')
  
  const {
    notificationTemplates,
    sendNotification,
    isNotificationActionLoading,
  } = useNotifications()

  const { useBookings } = useEvents()
  const { data: bookingsData } = useBookings({ page_size: 50 })

  const {
    register,
    handleSubmit,
    watch,
    reset,
    setValue,
    formState: { errors },
  } = useForm<SendNotificationFormData>({
    resolver: zodResolver(sendNotificationSchema),
    defaultValues: {
      notification_type: 'email',
      send_immediately: true,
      ...prefilledData,
    },
  })

  const watchedValues = watch()

  React.useEffect(() => {
    if (prefilledData) {
      Object.entries(prefilledData).forEach(([key, value]) => {
        setValue(key as keyof SendNotificationFormData, value)
      })
    }
  }, [prefilledData, setValue])

  const onSubmit = (data: SendNotificationFormData) => {
    sendNotification(data)
    onClose()
  }

  const handleTemplateSelect = (templateId: string) => {
    const template = notificationTemplates?.find(t => t.id === templateId)
    if (template) {
      setValue('template_id', templateId)
      setValue('notification_type', template.notification_type)
      setValue('subject', template.subject || '')
      setValue('message', template.message)
    }
  }

  const handleBookingSelect = (bookingId: string) => {
    const booking = bookingsData?.results?.find(b => b.id === bookingId)
    if (booking) {
      setValue('booking_id', bookingId)
      setValue('recipient_email', booking.invitee_email)
      if (booking.invitee_phone) {
        setValue('recipient_phone', booking.invitee_phone)
      }
    }
  }

  const templateOptions = notificationTemplates?.map(template => ({
    value: template.id,
    label: `${template.name} (${template.notification_type_display})`,
  })) || []

  const bookingOptions = bookingsData?.results?.map(booking => ({
    value: booking.id,
    label: `${booking.invitee_name} - ${booking.event_type.name} (${formatDateTime(booking.start_time)})`,
  })) || []

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Send Notification"
      size="lg"
    >
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Recipient Type Selection */}
        <div>
          <label className="block text-sm font-medium text-secondary-700 mb-3">
            How do you want to send this notification?
          </label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {recipientTypeOptions.map((option) => (
              <label key={option.value} className="relative">
                <input
                  type="radio"
                  name="recipientType"
                  value={option.value}
                  checked={recipientType === option.value}
                  onChange={(e) => setRecipientType(e.target.value)}
                  className="sr-only peer"
                />
                <div className="p-4 border-2 border-secondary-200 rounded-lg cursor-pointer peer-checked:border-primary-500 peer-checked:bg-primary-50 hover:border-secondary-300 transition-colors">
                  <div className="flex items-center space-x-3">
                    <div className="text-primary-600">{option.icon}</div>
                    <div>
                      <div className="font-medium text-secondary-900">{option.label}</div>
                    </div>
                  </div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Template Selection */}
        {recipientType === 'template' && (
          <Select
            options={templateOptions}
            value={watchedValues.template_id}
            onChange={(value) => handleTemplateSelect(value as string)}
            label="Select Template"
            placeholder="Choose a template"
            required
          />
        )}

        {/* Booking Selection */}
        {recipientType === 'booking' && (
          <Select
            options={bookingOptions}
            value={watchedValues.booking_id}
            onChange={(value) => handleBookingSelect(value as string)}
            label="Select Booking"
            placeholder="Choose a booking"
            searchable
            required
          />
        )}

        {/* Notification Type */}
        <Select
          options={notificationTypeOptions}
          value={watchedValues.notification_type}
          onChange={(value) => register('notification_type').onChange({ target: { value } })}
          label="Notification Type"
          error={errors.notification_type?.message}
          required
        />

        {/* Recipients */}
        {recipientType === 'manual' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {watchedValues.notification_type === 'email' && (
              <Input
                {...register('recipient_email')}
                type="email"
                label="Recipient Email"
                placeholder="recipient@example.com"
                error={errors.recipient_email?.message}
                required
              />
            )}

            {watchedValues.notification_type === 'sms' && (
              <Input
                {...register('recipient_phone')}
                type="tel"
                label="Recipient Phone"
                placeholder="+1 (555) 123-4567"
                error={errors.recipient_phone?.message}
                required
              />
            )}
          </div>
        )}

        {/* Content */}
        {watchedValues.notification_type === 'email' && (
          <Input
            {...register('subject')}
            label="Subject"
            placeholder="Email subject"
            error={errors.subject?.message}
            required
          />
        )}

        <Textarea
          {...register('message')}
          label="Message"
          placeholder="Your message content..."
          error={errors.message?.message}
          rows={6}
          required
        />

        {/* Scheduling */}
        <div className="space-y-4">
          <Checkbox
            {...register('send_immediately')}
            label="Send Immediately"
            description="Send this notification right away"
          />

          {!watchedValues.send_immediately && (
            <Input
              {...register('scheduled_for')}
              type="datetime-local"
              label="Schedule For"
              error={errors.scheduled_for?.message}
              required
            />
          )}
        </div>

        <div className="flex space-x-3">
          <Button type="button" variant="outline" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button
            type="submit"
            loading={isNotificationActionLoading}
            disabled={isNotificationActionLoading}
            className="flex-1"
            leftIcon={<Send className="h-4 w-4" />}
          >
            {watchedValues.send_immediately ? 'Send Now' : 'Schedule'}
          </Button>
        </div>
      </form>
    </Modal>
  )
}