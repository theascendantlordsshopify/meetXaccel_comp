import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Plus, Workflow, Play, Settings, Copy, Trash2, MoreHorizontal, TrendingUp, AlertTriangle, CheckCircle } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { Modal } from '@/components/ui/Modal'
import { useWorkflows } from '@/hooks/useWorkflows'
import { useToggle } from '@/hooks/useToggle'
import { ROUTES, buildRoute } from '@/constants/routes'
import { formatWorkflowTrigger } from '@/utils/format'
import { formatRelativeTime } from '@/utils/date'
import { cn } from '@/utils/cn'

export default function Workflows() {
  const { workflows, workflowsLoading, deleteWorkflow, testWorkflow, duplicateWorkflow, isWorkflowActionLoading } = useWorkflows()
  const [selectedWorkflow, setSelectedWorkflow] = useState<string | null>(null)
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()
  const [showTestModal, { toggle: toggleTestModal }] = useToggle()

  const handleDeleteWorkflow = () => {
    if (selectedWorkflow) {
      deleteWorkflow(selectedWorkflow)
      setSelectedWorkflow(null)
      toggleDeleteDialog()
    }
  }

  const handleTestWorkflow = (workflowId: string) => {
    setSelectedWorkflow(workflowId)
    toggleTestModal()
  }

  const handleDuplicateWorkflow = (workflowId: string) => {
    duplicateWorkflow(workflowId)
  }

  const selectedWorkflowData = workflows?.find(w => w.id === selectedWorkflow)

  if (workflowsLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Workflows"
        subtitle="Automate your booking processes with custom workflows"
        action={
          <Link to={ROUTES.WORKFLOW_CREATE}>
            <Button leftIcon={<Plus className="h-4 w-4" />}>
              Create Workflow
            </Button>
          </Link>
        }
      />

      <Container>
        {!workflows || workflows.length === 0 ? (
          <EmptyState
            icon={<Workflow className="h-12 w-12" />}
            title="No workflows yet"
            description="Create your first workflow to automate booking confirmations, reminders, and follow-ups"
            action={{
              label: 'Create Workflow',
              onClick: () => window.location.href = ROUTES.WORKFLOW_CREATE,
            }}
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {workflows.map((workflow) => (
              <Card
                key={workflow.id}
                className="group hover:shadow-medium transition-all duration-200"
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <h3 className="text-lg font-semibold text-secondary-900 group-hover:text-primary-900 transition-colors">
                        {workflow.name}
                      </h3>
                      <p className="text-sm text-secondary-600 mt-1 line-clamp-2">
                        {workflow.description || 'No description provided'}
                      </p>
                    </div>
                    <div className="flex items-center space-x-1 ml-4">
                      <StatusBadge status={workflow.is_active ? 'active' : 'inactive'} />
                      <div className="relative group/menu">
                        <Button variant="ghost" size="sm">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                        <div className="absolute right-0 top-full mt-1 w-48 bg-white rounded-lg shadow-strong border border-secondary-200 py-1 opacity-0 invisible group-hover/menu:opacity-100 group-hover/menu:visible transition-all duration-200 z-10">
                          <button
                            onClick={() => handleTestWorkflow(workflow.id)}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <Play className="h-4 w-4" />
                            <span>Test</span>
                          </button>
                          <Link
                            to={buildRoute.workflowEdit(workflow.id)}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <Settings className="h-4 w-4" />
                            <span>Edit</span>
                          </Link>
                          <button
                            onClick={() => handleDuplicateWorkflow(workflow.id)}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <Copy className="h-4 w-4" />
                            <span>Duplicate</span>
                          </button>
                          <hr className="my-1 border-secondary-100" />
                          <button
                            onClick={() => {
                              setSelectedWorkflow(workflow.id)
                              toggleDeleteDialog()
                            }}
                            className="w-full px-3 py-2 text-left text-sm text-error-600 hover:bg-error-50 flex items-center space-x-2"
                          >
                            <Trash2 className="h-4 w-4" />
                            <span>Delete</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardHeader>

                <CardContent>
                  <div className="space-y-4">
                    {/* Trigger Info */}
                    <div className="flex items-center space-x-2 text-sm text-secondary-600">
                      <div className="w-4 h-4 rounded-full bg-primary-100 flex items-center justify-center">
                        <div className="w-2 h-2 rounded-full bg-primary-600" />
                      </div>
                      <span>{formatWorkflowTrigger(workflow.trigger)}</span>
                    </div>

                    {/* Performance Metrics */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="text-center">
                        <div className="flex items-center justify-center space-x-1">
                          {workflow.execution_stats.success_rate >= 90 ? (
                            <CheckCircle className="h-4 w-4 text-success-500" />
                          ) : workflow.execution_stats.success_rate >= 70 ? (
                            <AlertTriangle className="h-4 w-4 text-warning-500" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-error-500" />
                          )}
                          <span className="text-lg font-semibold text-secondary-900">
                            {workflow.success_rate}%
                          </span>
                        </div>
                        <p className="text-xs text-secondary-500">Success Rate</p>
                      </div>
                      <div className="text-center">
                        <div className="flex items-center justify-center space-x-1">
                          <TrendingUp className="h-4 w-4 text-primary-500" />
                          <span className="text-lg font-semibold text-secondary-900">
                            {workflow.execution_stats.total_executions}
                          </span>
                        </div>
                        <p className="text-xs text-secondary-500">Executions</p>
                      </div>
                    </div>

                    {/* Actions Count */}
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-secondary-600">Actions:</span>
                      <span className="font-medium text-secondary-900">
                        {workflow.actions?.length || 0}
                      </span>
                    </div>

                    {/* Event Types */}
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-secondary-600">Event Types:</span>
                      <span className="font-medium text-secondary-900">
                        {workflow.event_types_count === 0 ? 'All' : workflow.event_types_count}
                      </span>
                    </div>

                    {/* Last Executed */}
                    {workflow.execution_stats.last_executed_at && (
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-secondary-600">Last run:</span>
                        <span className="text-secondary-900">
                          {formatRelativeTime(workflow.execution_stats.last_executed_at)}
                        </span>
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex space-x-2 pt-2 border-t border-secondary-100">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleTestWorkflow(workflow.id)}
                        className="flex-1"
                      >
                        <Play className="h-4 w-4 mr-2" />
                        Test
                      </Button>
                      <Link to={buildRoute.workflowEdit(workflow.id)} className="flex-1">
                        <Button variant="ghost" size="sm" fullWidth>
                          <Settings className="h-4 w-4 mr-2" />
                          Edit
                        </Button>
                      </Link>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </Container>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        onClose={toggleDeleteDialog}
        onConfirm={handleDeleteWorkflow}
        title="Delete Workflow"
        message="Are you sure you want to delete this workflow? This action cannot be undone and will stop all automated processes."
        confirmText="Delete"
        variant="danger"
      />

      {/* Test Workflow Modal */}
      <Modal
        isOpen={showTestModal}
        onClose={toggleTestModal}
        title="Test Workflow"
        size="md"
      >
        {selectedWorkflowData && (
          <div className="space-y-6">
            <div className="text-center">
              <Workflow className="h-12 w-12 text-primary-600 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                {selectedWorkflowData.name}
              </h3>
              <p className="text-secondary-600">
                Test this workflow with mock data to verify it works correctly.
              </p>
            </div>

            <div className="bg-secondary-50 p-4 rounded-lg">
              <h4 className="font-medium text-secondary-900 mb-2">Workflow Details</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-secondary-600">Trigger:</span>
                  <span className="text-secondary-900">{formatWorkflowTrigger(selectedWorkflowData.trigger)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-secondary-600">Actions:</span>
                  <span className="text-secondary-900">{selectedWorkflowData.actions?.length || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-secondary-600">Success Rate:</span>
                  <span className="text-secondary-900">{selectedWorkflowData.success_rate}%</span>
                </div>
              </div>
            </div>

            <div className="bg-info-50 border border-info-200 rounded-lg p-4">
              <h4 className="font-medium text-info-800 mb-2">What happens during testing?</h4>
              <ul className="text-sm text-info-700 space-y-1 list-disc list-inside">
                <li>Mock booking data will be used</li>
                <li>No real emails or SMS will be sent</li>
                <li>Webhooks will be called with test data</li>
                <li>Results will be logged for review</li>
              </ul>
            </div>

            <div className="flex space-x-3">
              <Button variant="outline" onClick={toggleTestModal} className="flex-1">
                Cancel
              </Button>
              <Button
                onClick={() => {
                  testWorkflow(selectedWorkflowData.id, { test_type: 'mock_data' })
                  toggleTestModal()
                }}
                loading={isWorkflowActionLoading}
                disabled={isWorkflowActionLoading}
                className="flex-1"
                leftIcon={<Play className="h-4 w-4" />}
              >
                Run Test
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}