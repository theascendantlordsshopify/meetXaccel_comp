import React, { useState } from 'react'
import { Template, Plus, Download, Star, Users, Clock, Mail, Webhook } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { Modal } from '@/components/ui/Modal'
import { Input } from '@/components/ui/Input'
import { useWorkflows } from '@/hooks/useWorkflows'
import { useToggle } from '@/hooks/useToggle'
import { ROUTES } from '@/constants/routes'

const templateCategories = [
  { value: '', label: 'All Categories' },
  { value: 'booking', label: 'Booking Management' },
  { value: 'follow_up', label: 'Follow-up' },
  { value: 'reminder', label: 'Reminders' },
  { value: 'feedback', label: 'Feedback Collection' },
]

const mockTemplates = [
  {
    id: '1',
    name: 'Booking Confirmation & Reminder',
    description: 'Send confirmation email immediately and reminder 1 hour before meeting',
    category: 'booking',
    usage_count: 1250,
    actions: [
      { type: 'send_email', name: 'Confirmation Email' },
      { type: 'send_email', name: 'Reminder Email' },
    ],
    preview: {
      trigger: 'booking_created',
      delay_minutes: 0,
      actions_count: 2,
    }
  },
  {
    id: '2',
    name: 'Follow-up Survey',
    description: 'Send feedback survey 24 hours after meeting completion',
    category: 'feedback',
    usage_count: 890,
    actions: [
      { type: 'send_email', name: 'Survey Email' },
      { type: 'webhook', name: 'CRM Update' },
    ],
    preview: {
      trigger: 'booking_completed',
      delay_minutes: 1440,
      actions_count: 2,
    }
  },
  {
    id: '3',
    name: 'No-Show Follow-up',
    description: 'Automatically follow up when invitee doesn\'t show up',
    category: 'follow_up',
    usage_count: 456,
    actions: [
      { type: 'update_booking', name: 'Mark as No-Show' },
      { type: 'send_email', name: 'Reschedule Email' },
    ],
    preview: {
      trigger: 'booking_completed',
      delay_minutes: 15,
      actions_count: 2,
    }
  },
  {
    id: '4',
    name: 'Multi-step Reminder',
    description: 'Send reminders at 24 hours, 2 hours, and 15 minutes before meeting',
    category: 'reminder',
    usage_count: 723,
    actions: [
      { type: 'send_email', name: '24h Reminder' },
      { type: 'send_email', name: '2h Reminder' },
      { type: 'send_sms', name: '15min SMS' },
    ],
    preview: {
      trigger: 'before_meeting',
      delay_minutes: 0,
      actions_count: 3,
    }
  },
]

export default function WorkflowTemplates() {
  const { createWorkflowFromTemplate, isWorkflowActionLoading } = useWorkflows()
  const [selectedCategory, setSelectedCategory] = useState('')
  const [selectedTemplate, setSelectedTemplate] = useState<any>(null)
  const [showPreviewModal, { toggle: togglePreviewModal }] = useToggle()
  const [showCreateModal, { toggle: toggleCreateModal }] = useToggle()
  const [workflowName, setWorkflowName] = useState('')

  const filteredTemplates = selectedCategory
    ? mockTemplates.filter(template => template.category === selectedCategory)
    : mockTemplates

  const handleUseTemplate = (template: any) => {
    setSelectedTemplate(template)
    setWorkflowName(template.name)
    toggleCreateModal()
  }

  const handlePreviewTemplate = (template: any) => {
    setSelectedTemplate(template)
    togglePreviewModal()
  }

  const handleCreateFromTemplate = () => {
    if (!selectedTemplate) return

    createWorkflowFromTemplate({
      template_id: selectedTemplate.id,
      name: workflowName,
    })
      .then(() => {
        toggleCreateModal()
        setSelectedTemplate(null)
        setWorkflowName('')
      })
      .catch(() => {
        // Error handling is done in the hook
      })
  }

  const getActionIcon = (actionType: string) => {
    switch (actionType) {
      case 'send_email':
        return <Mail className="h-4 w-4" />
      case 'send_sms':
        return <Mail className="h-4 w-4" />
      case 'webhook':
        return <Webhook className="h-4 w-4" />
      case 'update_booking':
        return <Clock className="h-4 w-4" />
      default:
        return <Star className="h-4 w-4" />
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'booking':
        return <Clock className="h-5 w-5" />
      case 'follow_up':
        return <Mail className="h-5 w-5" />
      case 'reminder':
        return <Clock className="h-5 w-5" />
      case 'feedback':
        return <Star className="h-5 w-5" />
      default:
        return <Template className="h-5 w-5" />
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Workflow Templates"
        subtitle="Get started quickly with pre-built workflow templates"
        breadcrumbs={[
          { label: 'Workflows', href: ROUTES.WORKFLOWS },
          { label: 'Templates', current: true },
        ]}
      />

      <Container>
        {/* Category Filter */}
        <div className="mb-6">
          <div className="flex items-center space-x-4">
            <label className="text-sm font-medium text-secondary-700">
              Filter by category:
            </label>
            <div className="flex space-x-2">
              {templateCategories.map((category) => (
                <Button
                  key={category.value}
                  variant={selectedCategory === category.value ? 'primary' : 'outline'}
                  size="sm"
                  onClick={() => setSelectedCategory(category.value)}
                >
                  {category.label}
                </Button>
              ))}
            </div>
          </div>
        </div>

        {/* Templates Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredTemplates.map((template) => (
            <Card
              key={template.id}
              className="group hover:shadow-medium transition-all duration-200 border-l-4 border-l-primary-500"
            >
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="p-2 bg-primary-100 rounded-lg text-primary-600">
                      {getCategoryIcon(template.category)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-lg font-semibold text-secondary-900 group-hover:text-primary-900 transition-colors">
                        {template.name}
                      </h3>
                      <Badge variant="secondary" size="sm" className="mt-1">
                        {templateCategories.find(c => c.value === template.category)?.label}
                      </Badge>
                    </div>
                  </div>
                </div>
              </CardHeader>

              <CardContent>
                <div className="space-y-4">
                  <p className="text-sm text-secondary-600">
                    {template.description}
                  </p>

                  {/* Template Stats */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center">
                      <div className="flex items-center justify-center space-x-1">
                        <Users className="h-4 w-4 text-secondary-400" />
                        <span className="text-lg font-semibold text-secondary-900">
                          {template.usage_count}
                        </span>
                      </div>
                      <p className="text-xs text-secondary-500">Uses</p>
                    </div>
                    <div className="text-center">
                      <div className="flex items-center justify-center space-x-1">
                        <Star className="h-4 w-4 text-secondary-400" />
                        <span className="text-lg font-semibold text-secondary-900">
                          {template.actions.length}
                        </span>
                      </div>
                      <p className="text-xs text-secondary-500">Actions</p>
                    </div>
                  </div>

                  {/* Actions Preview */}
                  <div>
                    <h4 className="text-sm font-medium text-secondary-900 mb-2">Actions:</h4>
                    <div className="space-y-1">
                      {template.actions.slice(0, 3).map((action, index) => (
                        <div key={index} className="flex items-center space-x-2 text-sm text-secondary-600">
                          {getActionIcon(action.type)}
                          <span>{action.name}</span>
                        </div>
                      ))}
                      {template.actions.length > 3 && (
                        <p className="text-xs text-secondary-500">
                          +{template.actions.length - 3} more actions
                        </p>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex space-x-2 pt-2 border-t border-secondary-100">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handlePreviewTemplate(template)}
                      className="flex-1"
                    >
                      Preview
                    </Button>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => handleUseTemplate(template)}
                      className="flex-1"
                    >
                      Use Template
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </Container>

      {/* Preview Modal */}
      <Modal
        isOpen={showPreviewModal}
        onClose={togglePreviewModal}
        title="Template Preview"
        size="lg"
      >
        {selectedTemplate && (
          <div className="space-y-6">
            <div className="text-center">
              <div className="p-3 bg-primary-100 rounded-lg text-primary-600 w-fit mx-auto mb-4">
                {getCategoryIcon(selectedTemplate.category)}
              </div>
              <h3 className="text-xl font-bold text-secondary-900 mb-2">
                {selectedTemplate.name}
              </h3>
              <p className="text-secondary-600">
                {selectedTemplate.description}
              </p>
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="bg-secondary-50 p-4 rounded-lg text-center">
                <p className="text-sm font-medium text-secondary-900">Trigger</p>
                <p className="text-xs text-secondary-600 mt-1">
                  {selectedTemplate.preview.trigger.replace('_', ' ')}
                </p>
              </div>
              <div className="bg-secondary-50 p-4 rounded-lg text-center">
                <p className="text-sm font-medium text-secondary-900">Delay</p>
                <p className="text-xs text-secondary-600 mt-1">
                  {selectedTemplate.preview.delay_minutes === 0 
                    ? 'Immediate' 
                    : `${selectedTemplate.preview.delay_minutes} min`
                  }
                </p>
              </div>
              <div className="bg-secondary-50 p-4 rounded-lg text-center">
                <p className="text-sm font-medium text-secondary-900">Actions</p>
                <p className="text-xs text-secondary-600 mt-1">
                  {selectedTemplate.preview.actions_count}
                </p>
              </div>
            </div>

            <div>
              <h4 className="font-medium text-secondary-900 mb-3">Actions in this template:</h4>
              <div className="space-y-3">
                {selectedTemplate.actions.map((action, index) => (
                  <div key={index} className="flex items-center space-x-3 p-3 bg-secondary-50 rounded-lg">
                    <div className="p-2 bg-white rounded border">
                      {getActionIcon(action.type)}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-secondary-900">{action.name}</p>
                      <p className="text-xs text-secondary-600 capitalize">
                        {action.type.replace('_', ' ')}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-info-50 border border-info-200 rounded-lg p-4">
              <h4 className="font-medium text-info-800 mb-2">Popular Template</h4>
              <p className="text-sm text-info-700">
                This template has been used by {selectedTemplate.usage_count.toLocaleString()} users and is highly rated for its effectiveness.
              </p>
            </div>

            <div className="flex space-x-3">
              <Button variant="outline" onClick={togglePreviewModal} className="flex-1">
                Close
              </Button>
              <Button
                onClick={() => {
                  togglePreviewModal()
                  handleUseTemplate(selectedTemplate)
                }}
                className="flex-1"
                leftIcon={<Download className="h-4 w-4" />}
              >
                Use This Template
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Create from Template Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={toggleCreateModal}
        title="Create Workflow from Template"
        size="md"
      >
        {selectedTemplate && (
          <div className="space-y-6">
            <div className="text-center">
              <div className="p-3 bg-primary-100 rounded-lg text-primary-600 w-fit mx-auto mb-4">
                {getCategoryIcon(selectedTemplate.category)}
              </div>
              <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                {selectedTemplate.name}
              </h3>
              <p className="text-sm text-secondary-600">
                Customize the workflow name or use the default
              </p>
            </div>

            <Input
              label="Workflow Name"
              value={workflowName}
              onChange={(e) => setWorkflowName(e.target.value)}
              placeholder="Enter workflow name"
              required
            />

            <div className="bg-secondary-50 p-4 rounded-lg">
              <h4 className="font-medium text-secondary-900 mb-2">What will be created:</h4>
              <ul className="text-sm text-secondary-600 space-y-1">
                <li>• Workflow with {selectedTemplate.actions.length} pre-configured actions</li>
                <li>• Email templates with professional content</li>
                <li>• Proper trigger and timing settings</li>
                <li>• Ready to activate immediately</li>
              </ul>
            </div>

            <div className="flex space-x-3">
              <Button variant="outline" onClick={toggleCreateModal} className="flex-1">
                Cancel
              </Button>
              <Button
                onClick={handleCreateFromTemplate}
                loading={isWorkflowActionLoading}
                disabled={isWorkflowActionLoading || !workflowName.trim()}
                className="flex-1"
                leftIcon={<Plus className="h-4 w-4" />}
              >
                Create Workflow
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}