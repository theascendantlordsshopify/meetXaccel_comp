import React from 'react'
import { Mail, MessageSquare, Eye } from 'lucide-react'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Modal } from '@/components/ui/Modal'
import { formatDateTime } from '@/utils/date'
import type { NotificationTemplate } from '@/types'

interface NotificationPreviewProps {
  isOpen: boolean
  onClose: () => void
  template: NotificationTemplate | null
  sampleData?: Record<string, any>
}

export function NotificationPreview({ 
  isOpen, 
  onClose, 
  template, 
  sampleData 
}: NotificationPreviewProps) {
  if (!template) return null

  // Sample data for preview
  const defaultSampleData = {
    invitee_name: 'John Doe',
    invitee_email: 'john.doe@example.com',
    organizer_name: 'Jane Smith',
    event_name: 'Discovery Call',
    start_time: 'Tomorrow at 2:00 PM',
    duration: '30 minutes',
    meeting_link: 'https://zoom.us/j/123456789',
    meeting_id: '123 456 789',
    meeting_password: 'abc123',
    location: 'Video Call',
    timezone: 'Eastern Time',
    ...sampleData,
  }

  // Simple template rendering (replace {{placeholder}} with values)
  const renderTemplate = (content: string) => {
    let rendered = content
    Object.entries(defaultSampleData).forEach(([key, value]) => {
      const placeholder = `{{${key}}}`
      rendered = rendered.replace(new RegExp(placeholder, 'g'), String(value))
    })
    return rendered
  }

  const renderedSubject = template.subject ? renderTemplate(template.subject) : ''
  const renderedMessage = renderTemplate(template.message)

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Template Preview"
      size="lg"
    >
      <div className="space-y-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-primary-100 rounded-lg">
            {template.notification_type === 'email' ? (
              <Mail className="h-5 w-5 text-primary-600" />
            ) : (
              <MessageSquare className="h-5 w-5 text-primary-600" />
            )}
          </div>
          <div>
            <h3 className="text-lg font-semibold text-secondary-900">
              {template.name}
            </h3>
            <div className="flex items-center space-x-2">
              <Badge variant="secondary" size="sm">
                {template.template_type_display}
              </Badge>
              <Badge variant="primary" size="sm">
                {template.notification_type_display}
              </Badge>
            </div>
          </div>
        </div>

        {/* Preview Content */}
        <Card>
          <CardHeader title="Preview with Sample Data" />
          <CardContent>
            {template.notification_type === 'email' ? (
              <div className="space-y-4">
                {/* Email Header */}
                <div className="bg-secondary-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between text-sm text-secondary-600">
                    <div>
                      <p><strong>From:</strong> noreply@calendlyclone.com</p>
                      <p><strong>To:</strong> {defaultSampleData.invitee_email}</p>
                      <p><strong>Subject:</strong> {renderedSubject}</p>
                    </div>
                    <div className="text-right">
                      <p>{formatDateTime(new Date())}</p>
                    </div>
                  </div>
                </div>

                {/* Email Body */}
                <div className="bg-white border border-secondary-200 rounded-lg p-6">
                  <div className="whitespace-pre-wrap text-secondary-900">
                    {renderedMessage}
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                {/* SMS Header */}
                <div className="bg-secondary-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between text-sm text-secondary-600">
                    <div>
                      <p><strong>To:</strong> +1 (555) 123-4567</p>
                      <p><strong>From:</strong> Calendly Clone</p>
                    </div>
                    <div className="text-right">
                      <p>{formatDateTime(new Date())}</p>
                    </div>
                  </div>
                </div>

                {/* SMS Body */}
                <div className="bg-blue-500 text-white p-4 rounded-lg max-w-sm ml-auto">
                  <div className="whitespace-pre-wrap text-sm">
                    {renderedMessage}
                  </div>
                  <div className="text-xs opacity-75 mt-2 text-right">
                    {formatDateTime(new Date(), 'h:mm a')}
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Sample Data Used */}
        <Card>
          <CardHeader title="Sample Data Used" />
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-sm">
              {Object.entries(defaultSampleData).map(([key, value]) => (
                <div key={key} className="flex justify-between">
                  <span className="text-secondary-600">{{`{{${key}}}`}}:</span>
                  <span className="font-medium text-secondary-900">{String(value)}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <div className="flex justify-end">
          <Button onClick={onClose}>
            Close Preview
          </Button>
        </div>
      </div>
    </Modal>
  )
}