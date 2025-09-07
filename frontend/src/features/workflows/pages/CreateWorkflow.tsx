import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, Workflow, Plus, Trash2, Save } from 'lucide-react'
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
import { useWorkflows } from '@/hooks/useWorkflows'
import { useEvents } from '@/hooks/useEvents'
import { ROUTES } from '@/constants/routes'
import { WORKFLOW_TRIGGERS, WORKFLOW_ACTION_TYPES } from '@/constants'
import { workflowSchema, workflowActionSchema, type WorkflowFormData, type WorkflowActionFormData } from '@/types/forms'

const recipientOptions = [
  { value: 'organizer', label: 'Organizer' },
  { value: 'invitee', label: 'Invitee' },
  { value: 'both', label: 'Both' },
  { value: 'custom', label: 'Custom Email' },
]

export default function CreateWorkflow() {
  const navigate = useNavigate()
  const { createWorkflow, isWorkflowActionLoading } = useWorkflows()
  const { eventTypes } = useEvents()

  const {
    register,
    control,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<WorkflowFormData & { actions: WorkflowActionFormData[] }>({
    resolver: zodResolver(workflowSchema.extend({
      actions: workflowActionSchema.array().min(1, 'At least one action is required')
    })),
    defaultValues: {
      trigger: 'booking_created',
      delay_minutes: 0,
      is_active: true,
      actions: [{
        name: 'Send confirmation email',
        action_type: 'send_email',
        order: 1,
        recipient: 'invitee',
        subject: 'Booking Confirmed: {{event_name}}',
        message: `Hi {{invitee_name}},

Your booking has been confirmed!

Event: {{event_name}}
Date & Time: {{start_time_invitee}}
Duration: {{duration}}

Best regards,
{{organizer_name}}`,
        is_active: true,
      }],
    },
  })

  const { fields: actions, append: addAction, remove: removeAction } = useFieldArray({
    control,
    name: 'actions',
  })

  const watchedValues = watch()

  const onSubmit = (data: WorkflowFormData & { actions: WorkflowActionFormData[] }) => {
    const { actions, ...workflowData } = data
    
    createWorkflow({
      ...workflowData,
      actions_data: actions,
    })
      .then(() => {
        navigate(ROUTES.WORKFLOWS)
      })
      .catch(() => {
        // Error handling is done in the hook
      })
  }

  const addNewAction = () => {
    addAction({
      name: '',
      action_type: 'send_email',
      order: actions.length + 1,
      recipient: 'invitee',
      subject: '',
      message: '',
      is_active: true,
    })
  }

  const eventTypeOptions = eventTypes?.map(et => ({
    value: et.id,
    label: et.name,
  })) || []

  return (
    <div className="space-y-8">
      <PageHeader
        title="Create Workflow"
        subtitle="Set up automated processes for your bookings"
        breadcrumbs={[
          { label: 'Workflows', href: ROUTES.WORKFLOWS },
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
                  label="Workflow Name"
                  placeholder="e.g., Booking Confirmation Flow"
                  error={errors.name?.message}
                  required
                />

                <Textarea
                  {...register('description')}
                  label="Description"
                  placeholder="Describe what this workflow does..."
                  error={errors.description?.message}
                  rows={3}
                />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <Select
                    options={WORKFLOW_TRIGGERS}
                    value={watchedValues.trigger}
                    onChange={(value) => register('trigger').onChange({ target: { value } })}
                    label="Trigger Event"
                    error={errors.trigger?.message}
                    required
                  />

                  <Input
                    {...register('delay_minutes', { valueAsNumber: true })}
                    type="number"
                    label="Delay (minutes)"
                    placeholder="0"
                    min={0}
                    max={10080}
                    error={errors.delay_minutes?.message}
                    helpText="Delay before executing actions"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-secondary-700 mb-2">
                    Event Types (optional)
                  </label>
                  <Select
                    options={eventTypeOptions}
                    value={watchedValues.event_types}
                    onChange={(value) => register('event_types').onChange({ target: { value } })}
                    placeholder="All event types"
                    multiple
                    helpText="Leave empty to apply to all event types"
                  />
                </div>

                <Checkbox
                  {...register('is_active')}
                  label="Active"
                  description="Enable this workflow to run automatically"
                />
              </CardContent>
            </Card>

            {/* Actions */}
            <Card>
              <CardHeader
                title="Actions"
                subtitle="Define what happens when this workflow is triggered"
                action={
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={addNewAction}
                    leftIcon={<Plus className="h-4 w-4" />}
                  >
                    Add Action
                  </Button>
                }
              />
              <CardContent>
                {actions.length === 0 ? (
                  <div className="text-center py-8">
                    <p className="text-secondary-500 mb-4">No actions added yet</p>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={addNewAction}
                      leftIcon={<Plus className="h-4 w-4" />}
                    >
                      Add Your First Action
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {actions.map((action, index) => (
                      <Card key={action.id} variant="outlined">
                        <CardContent className="p-4">
                          <div className="flex items-start justify-between mb-4">
                            <h4 className="font-medium text-secondary-900">
                              Action {index + 1}
                            </h4>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => removeAction(index)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>

                          <div className="space-y-4">
                            <Input
                              {...register(`actions.${index}.name`)}
                              label="Action Name"
                              placeholder="What does this action do?"
                              error={errors.actions?.[index]?.name?.message}
                              required
                            />

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <Select
                                options={WORKFLOW_ACTION_TYPES}
                                value={watchedValues.actions?.[index]?.action_type}
                                onChange={(value) => 
                                  register(`actions.${index}.action_type`).onChange({ target: { value } })
                                }
                                label="Action Type"
                                error={errors.actions?.[index]?.action_type?.message}
                                required
                              />

                              <Input
                                {...register(`actions.${index}.order`, { valueAsNumber: true })}
                                type="number"
                                label="Order"
                                min={1}
                                error={errors.actions?.[index]?.order?.message}
                                required
                              />
                            </div>

                            {/* Email/SMS specific fields */}
                            {['send_email', 'send_sms'].includes(watchedValues.actions?.[index]?.action_type) && (
                              <>
                                <Select
                                  options={recipientOptions}
                                  value={watchedValues.actions?.[index]?.recipient}
                                  onChange={(value) => 
                                    register(`actions.${index}.recipient`).onChange({ target: { value } })
                                  }
                                  label="Recipient"
                                  error={errors.actions?.[index]?.recipient?.message}
                                  required
                                />

                                {watchedValues.actions?.[index]?.recipient === 'custom' && (
                                  <Input
                                    {...register(`actions.${index}.custom_email`)}
                                    type="email"
                                    label="Custom Email"
                                    placeholder="recipient@example.com"
                                    error={errors.actions?.[index]?.custom_email?.message}
                                    required
                                  />
                                )}

                                {watchedValues.actions?.[index]?.action_type === 'send_email' && (
                                  <Input
                                    {...register(`actions.${index}.subject`)}
                                    label="Subject"
                                    placeholder="Email subject with {{placeholders}}"
                                    error={errors.actions?.[index]?.subject?.message}
                                    required
                                  />
                                )}

                                <Textarea
                                  {...register(`actions.${index}.message`)}
                                  label="Message"
                                  placeholder="Message content with {{placeholders}}"
                                  error={errors.actions?.[index]?.message?.message}
                                  rows={4}
                                  required
                                />
                              </>
                            )}

                            {/* Webhook specific fields */}
                            {watchedValues.actions?.[index]?.action_type === 'webhook' && (
                              <>
                                <Input
                                  {...register(`actions.${index}.webhook_url`)}
                                  type="url"
                                  label="Webhook URL"
                                  placeholder="https://your-service.com/webhook"
                                  error={errors.actions?.[index]?.webhook_url?.message}
                                  required
                                />

                                <Textarea
                                  {...register(`actions.${index}.webhook_data`)}
                                  label="Custom Data (JSON)"
                                  placeholder='{"key": "value"}'
                                  error={errors.actions?.[index]?.webhook_data?.message}
                                  rows={3}
                                  helpText="Additional data to send with the webhook"
                                />
                              </>
                            )}

                            {/* Update booking specific fields */}
                            {watchedValues.actions?.[index]?.action_type === 'update_booking' && (
                              <Textarea
                                {...register(`actions.${index}.update_booking_fields`)}
                                label="Fields to Update (JSON)"
                                placeholder='{"status": "completed", "custom_answers": {"feedback": "positive"}}'
                                error={errors.actions?.[index]?.update_booking_fields?.message}
                                rows={3}
                                required
                                helpText="JSON object with booking fields to update"
                              />
                            )}

                            <Checkbox
                              {...register(`actions.${index}.is_active`)}
                              label="Active"
                              description="Enable this action"
                            />
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
                onClick={() => navigate(ROUTES.WORKFLOWS)}
                leftIcon={<ArrowLeft className="h-4 w-4" />}
              >
                Back to Workflows
              </Button>

              <div className="flex space-x-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate(ROUTES.WORKFLOWS)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  loading={isWorkflowActionLoading}
                  disabled={isWorkflowActionLoading}
                  leftIcon={<Save className="h-4 w-4" />}
                >
                  Create Workflow
                </Button>
              </div>
            </div>
          </form>
        </div>
      </Container>
    </div>
  )
}