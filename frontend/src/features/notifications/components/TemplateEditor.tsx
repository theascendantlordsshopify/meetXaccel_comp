import React, { useState } from 'react'
import { Eye, Code, Save } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
import { NotificationPreview } from './NotificationPreview'
import { useToggle } from '@/hooks/useToggle'
import type { NotificationTemplate } from '@/types'

interface TemplateEditorProps {
  template?: NotificationTemplate | null
  onSave: (data: any) => void
  isLoading?: boolean
}

const templateTypeOptions = [
  { value: 'booking_confirmation', label: 'Booking Confirmation' },
  { value: 'booking_reminder', label: 'Booking Reminder' },
  { value: 'booking_cancellation', label: 'Booking Cancellation' },
  { value: 'booking_rescheduled', label: 'Booking Rescheduled' },
  { value: 'follow_up', label: 'Follow-up' },
  { value: 'custom', label: 'Custom' },
]

const notificationTypeOptions = [
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'SMS' },
]

export function TemplateEditor({ template, onSave, isLoading = false }: TemplateEditorProps) {
  const [formData, setFormData] = useState({
    name: template?.name || '',
    template_type: template?.template_type || 'booking_confirmation',
    notification_type: template?.notification_type || 'email',
    subject: template?.subject || '',
    message: template?.message || '',
    is_active: template?.is_active ?? true,
    is_default: template?.is_default ?? false,
  })

  const [showPreview, { toggle: togglePreview }] = useToggle()

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave(formData)
  }

  const handleFieldChange = (field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="space-y-6">
        <Card>
          <CardHeader title="Template Information" />
          <CardContent className="space-y-6">
            <Input
              label="Template Name"
              value={formData.name}
              onChange={(e) => handleFieldChange('name', e.target.value)}
              placeholder="e.g., Custom Booking Confirmation"
              required
            />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Select
                options={templateTypeOptions}
                value={formData.template_type}
                onChange={(value) => handleFieldChange('template_type', value)}
                label="Template Type"
                required
              />

              <Select
                options={notificationTypeOptions}
                value={formData.notification_type}
                onChange={(value) => handleFieldChange('notification_type', value)}
                label="Notification Type"
                required
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader
            title="Content"
            action={
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={togglePreview}
                leftIcon={<Eye className="h-4 w-4" />}
              >
                Preview
              </Button>
            }
          />
          <CardContent className="space-y-6">
            {formData.notification_type === 'email' && (
              <Input
                label="Subject"
                value={formData.subject}
                onChange={(e) => handleFieldChange('subject', e.target.value)}
                placeholder="Email subject with {{placeholders}}"
                required
              />
            )}

            <Textarea
              label="Message"
              value={formData.message}
              onChange={(e) => handleFieldChange('message', e.target.value)}
              placeholder="Message content with {{placeholders}}"
              rows={12}
              required
            />

            <div className="bg-info-50 border border-info-200 rounded-lg p-4">
              <h4 className="font-medium text-info-800 mb-2">Available Placeholders</h4>
              <div className="grid grid-cols-2 gap-4 text-sm text-info-700">
                <div>
                  <p className="font-medium mb-2">Booking Information:</p>
                  <ul className="space-y-1 text-xs font-mono">
                    <li>{{`{{invitee_name}}`}}</li>
                    <li>{{`{{invitee_email}}`}}</li>
                    <li>{{`{{organizer_name}}`}}</li>
                    <li>{{`{{event_name}}`}}</li>
                    <li>{{`{{start_time}}`}}</li>
                    <li>{{`{{end_time}}`}}</li>
                    <li>{{`{{duration}}`}}</li>
                    <li>{{`{{timezone}}`}}</li>
                  </ul>
                </div>
                <div>
                  <p className="font-medium mb-2">Meeting Details:</p>
                  <ul className="space-y-1 text-xs font-mono">
                    <li>{{`{{meeting_link}}`}}</li>
                    <li>{{`{{meeting_id}}`}}</li>
                    <li>{{`{{meeting_password}}`}}</li>
                    <li>{{`{{location}}`}}</li>
                    <li>{{`{{booking_url}}`}}</li>
                    <li>{{`{{cancel_url}}`}}</li>
                    <li>{{`{{reschedule_url}}`}}</li>
                    <li>{{`{{cancellation_reason}}`}}</li>
                  </ul>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader title="Settings" />
          <CardContent className="space-y-6">
            <div className="grid grid-cols-2 gap-6">
              <Checkbox
                checked={formData.is_active}
                onChange={(checked) => handleFieldChange('is_active', checked)}
                label="Active"
                description="Enable this template for use"
              />

              <Checkbox
                checked={formData.is_default}
                onChange={(checked) => handleFieldChange('is_default', checked)}
                label="Default Template"
                description="Use as default for this notification type"
              />
            </div>
          </CardContent>
        </Card>

        <div className="flex justify-end space-x-3">
          <Button
            type="submit"
            loading={isLoading}
            disabled={isLoading}
            leftIcon={<Save className="h-4 w-4" />}
          >
            {template ? 'Save Changes' : 'Create Template'}
          </Button>
        </div>
      </form>

      {/* Preview Modal */}
      <NotificationPreview
        isOpen={showPreview}
        onClose={togglePreview}
        template={formData as any}
      />
    </div>
  )
}