import React from 'react'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { WORKFLOW_ACTION_TYPES } from '@/constants'

interface ActionEditorProps {
  action: any
  onChange: (field: string, value: any) => void
  errors?: Record<string, string>
}

const recipientOptions = [
  { value: 'organizer', label: 'Organizer' },
  { value: 'invitee', label: 'Invitee' },
  { value: 'both', label: 'Both' },
  { value: 'custom', label: 'Custom Email' },
]

export function ActionEditor({ action, onChange, errors = {} }: ActionEditorProps) {
  return (
    <Card>
      <CardHeader title="Action Configuration" />
      <CardContent className="space-y-6">
        <Input
          label="Action Name"
          value={action.name || ''}
          onChange={(e) => onChange('name', e.target.value)}
          placeholder="What does this action do?"
          error={errors.name}
          required
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Select
            options={WORKFLOW_ACTION_TYPES}
            value={action.action_type}
            onChange={(value) => onChange('action_type', value)}
            label="Action Type"
            error={errors.action_type}
            required
          />

          <Input
            type="number"
            label="Order"
            value={action.order || 1}
            onChange={(e) => onChange('order', parseInt(e.target.value))}
            min={1}
            error={errors.order}
            required
          />
        </div>

        {/* Email/SMS specific fields */}
        {['send_email', 'send_sms'].includes(action.action_type) && (
          <>
            <Select
              options={recipientOptions}
              value={action.recipient}
              onChange={(value) => onChange('recipient', value)}
              label="Recipient"
              error={errors.recipient}
              required
            />

            {action.recipient === 'custom' && (
              <Input
                type="email"
                label="Custom Email"
                value={action.custom_email || ''}
                onChange={(e) => onChange('custom_email', e.target.value)}
                placeholder="recipient@example.com"
                error={errors.custom_email}
                required
              />
            )}

            {action.action_type === 'send_email' && (
              <Input
                label="Subject"
                value={action.subject || ''}
                onChange={(e) => onChange('subject', e.target.value)}
                placeholder="Email subject with {{placeholders}}"
                error={errors.subject}
                required
              />
            )}

            <Textarea
              label="Message"
              value={action.message || ''}
              onChange={(e) => onChange('message', e.target.value)}
              placeholder="Message content with {{placeholders}}"
              error={errors.message}
              rows={6}
              required
            />

            <div className="bg-info-50 border border-info-200 rounded-lg p-4">
              <h4 className="font-medium text-info-800 mb-2">Available Placeholders</h4>
              <div className="grid grid-cols-2 gap-2 text-sm text-info-700">
                <div>
                  <p className="font-medium mb-1">Booking Info:</p>
                  <ul className="space-y-1 text-xs">
                    <li>{{`{{invitee_name}}`}}</li>
                    <li>{{`{{invitee_email}}`}}</li>
                    <li>{{`{{organizer_name}}`}}</li>
                    <li>{{`{{event_name}}`}}</li>
                    <li>{{`{{start_time}}`}}</li>
                    <li>{{`{{duration}}`}}</li>
                  </ul>
                </div>
                <div>
                  <p className="font-medium mb-1">Meeting Info:</p>
                  <ul className="space-y-1 text-xs">
                    <li>{{`{{meeting_link}}`}}</li>
                    <li>{{`{{meeting_id}}`}}</li>
                    <li>{{`{{meeting_password}}`}}</li>
                    <li>{{`{{location}}`}}</li>
                    <li>{{`{{timezone}}`}}</li>
                  </ul>
                </div>
              </div>
            </div>
          </>
        )}

        {/* Webhook specific fields */}
        {action.action_type === 'webhook' && (
          <>
            <Input
              type="url"
              label="Webhook URL"
              value={action.webhook_url || ''}
              onChange={(e) => onChange('webhook_url', e.target.value)}
              placeholder="https://your-service.com/webhook"
              error={errors.webhook_url}
              required
            />

            <Textarea
              label="Custom Data (JSON)"
              value={typeof action.webhook_data === 'string' ? action.webhook_data : JSON.stringify(action.webhook_data || {}, null, 2)}
              onChange={(e) => {
                try {
                  const parsed = JSON.parse(e.target.value)
                  onChange('webhook_data', parsed)
                } catch {
                  onChange('webhook_data', e.target.value)
                }
              }}
              placeholder='{"key": "value"}'
              error={errors.webhook_data}
              rows={4}
              helpText="Additional data to send with the webhook"
            />
          </>
        )}

        {/* Update booking specific fields */}
        {action.action_type === 'update_booking' && (
          <Textarea
            label="Fields to Update (JSON)"
            value={typeof action.update_booking_fields === 'string' ? action.update_booking_fields : JSON.stringify(action.update_booking_fields || {}, null, 2)}
            onChange={(e) => {
              try {
                const parsed = JSON.parse(e.target.value)
                onChange('update_booking_fields', parsed)
              } catch {
                onChange('update_booking_fields', e.target.value)
              }
            }}
            placeholder='{"status": "completed", "custom_answers": {"feedback": "positive"}}'
            error={errors.update_booking_fields}
            rows={4}
            required
            helpText="JSON object with booking fields to update"
          />
        )}

        <Checkbox
          checked={action.is_active}
          onChange={(checked) => onChange('is_active', checked)}
          label="Active"
          description="Enable this action"
        />
      </CardContent>
    </Card>
  )
}