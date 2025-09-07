import React, { useState } from 'react'
import { Play, CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { Modal } from '@/components/ui/Modal'
import { useWorkflows } from '@/hooks/useWorkflows'
import { useEvents } from '@/hooks/useEvents'

interface WorkflowTesterProps {
  isOpen: boolean
  onClose: () => void
  workflowId: string
  workflowName: string
}

const testTypeOptions = [
  { 
    value: 'mock_data', 
    label: 'Mock Data Test',
    description: 'Test with fake data - no real actions will be performed'
  },
  { 
    value: 'real_data', 
    label: 'Real Data Test',
    description: 'Test with real booking data but no real actions'
  },
  { 
    value: 'live_test', 
    label: 'Live Test',
    description: 'Full test with real actions - emails/SMS will be sent!'
  },
]

export function WorkflowTester({ isOpen, onClose, workflowId, workflowName }: WorkflowTesterProps) {
  const [testType, setTestType] = useState('mock_data')
  const [selectedBookingId, setSelectedBookingId] = useState('')
  const [testStatus, setTestStatus] = useState<'idle' | 'running' | 'completed' | 'failed'>('idle')
  const [testResults, setTestResults] = useState<any>(null)

  const { testWorkflow } = useWorkflows()
  const { useBookings } = useEvents()

  // Get recent bookings for real data testing
  const { data: bookingsData } = useBookings({
    page_size: 10,
    status: 'confirmed',
  })

  const bookingOptions = bookingsData?.results?.map(booking => ({
    value: booking.id,
    label: `${booking.invitee_name} - ${booking.event_type.name} (${formatDate(booking.start_time)})`,
  })) || []

  const handleRunTest = async () => {
    setTestStatus('running')
    setTestResults(null)

    try {
      const testData: any = { test_type: testType }
      
      if (testType !== 'mock_data' && selectedBookingId) {
        testData.booking_id = selectedBookingId
      }
      
      if (testType === 'live_test') {
        testData.live_test = true
      }

      // Simulate test execution
      await new Promise(resolve => setTimeout(resolve, 2000))
      
      // Mock test results
      const mockResults = {
        workflow_id: workflowId,
        test_type: testType,
        status: 'completed',
        actions_executed: 3,
        actions_failed: 0,
        execution_time_ms: 1250,
        results: [
          {
            action_name: 'Send confirmation email',
            action_type: 'send_email',
            status: 'success',
            result: testType === 'mock_data' 
              ? { test_mode: true, recipients: ['test@example.com'] }
              : { notification_id: 'notif_123', status: 'queued' }
          },
          {
            action_name: 'Update CRM',
            action_type: 'webhook',
            status: 'success',
            result: { status_code: 200, response_time: '245ms' }
          },
          {
            action_name: 'Send reminder',
            action_type: 'send_email',
            status: 'success',
            result: { scheduled_for: '2024-01-15T14:00:00Z' }
          }
        ]
      }

      setTestResults(mockResults)
      setTestStatus('completed')
    } catch (error) {
      setTestStatus('failed')
      setTestResults({ error: 'Test execution failed' })
    }
  }

  const getStatusIcon = () => {
    switch (testStatus) {
      case 'running':
        return <Clock className="h-5 w-5 text-warning-500" />
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-success-500" />
      case 'failed':
        return <XCircle className="h-5 w-5 text-error-500" />
      default:
        return <Play className="h-5 w-5 text-secondary-500" />
    }
  }

  const getStatusColor = () => {
    switch (testStatus) {
      case 'running':
        return 'warning'
      case 'completed':
        return 'success'
      case 'failed':
        return 'error'
      default:
        return 'secondary'
    }
  }

  const handleClose = () => {
    setTestStatus('idle')
    setTestResults(null)
    setTestType('mock_data')
    setSelectedBookingId('')
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Test Workflow"
      size="lg"
    >
      <div className="space-y-6">
        <div className="text-center">
          <div className="p-3 bg-primary-100 rounded-lg text-primary-600 w-fit mx-auto mb-4">
            <Play className="h-8 w-8" />
          </div>
          <h3 className="text-lg font-semibold text-secondary-900 mb-2">
            Test: {workflowName}
          </h3>
          <p className="text-secondary-600">
            Choose how you want to test this workflow
          </p>
        </div>

        {/* Test Configuration */}
        <Card>
          <CardHeader title="Test Configuration" />
          <CardContent className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-secondary-700 mb-2">
                Test Type
              </label>
              <div className="space-y-3">
                {testTypeOptions.map((option) => (
                  <label key={option.value} className="relative">
                    <input
                      type="radio"
                      name="testType"
                      value={option.value}
                      checked={testType === option.value}
                      onChange={(e) => setTestType(e.target.value)}
                      className="sr-only peer"
                    />
                    <div className="p-4 border-2 border-secondary-200 rounded-lg cursor-pointer peer-checked:border-primary-500 peer-checked:bg-primary-50 hover:border-secondary-300 transition-colors">
                      <div className="flex items-start space-x-3">
                        <div className="flex-1">
                          <div className="font-medium text-secondary-900">{option.label}</div>
                          <div className="text-sm text-secondary-600">{option.description}</div>
                        </div>
                        {option.value === 'live_test' && (
                          <Badge variant="warning" size="sm">Caution</Badge>
                        )}
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {testType !== 'mock_data' && (
              <Select
                options={bookingOptions}
                value={selectedBookingId}
                onChange={(value) => setSelectedBookingId(value as string)}
                label="Select Booking"
                placeholder="Choose a booking to test with"
                required
                searchable
              />
            )}
          </CardContent>
        </Card>

        {/* Test Status */}
        <Card>
          <CardHeader title="Test Status" />
          <CardContent>
            <div className="flex items-center space-x-3">
              {getStatusIcon()}
              <div className="flex-1">
                <p className="text-sm font-medium text-secondary-900">
                  {testStatus === 'idle' && 'Ready to test'}
                  {testStatus === 'running' && 'Running workflow test...'}
                  {testStatus === 'completed' && 'Test completed successfully!'}
                  {testStatus === 'failed' && 'Test failed'}
                </p>
                {testResults && testStatus === 'completed' && (
                  <p className="text-xs text-secondary-500">
                    Execution time: {testResults.execution_time_ms}ms
                  </p>
                )}
              </div>
              <Badge variant={getStatusColor()} size="sm">
                {testStatus}
              </Badge>
            </div>

            {testStatus === 'running' && (
              <div className="mt-4">
                <LoadingSpinner size="sm" />
              </div>
            )}

            {testResults && testStatus === 'completed' && (
              <div className="mt-4 space-y-3">
                <div className="bg-success-50 p-3 rounded-lg">
                  <p className="text-sm font-medium text-success-900">
                    {testResults.actions_executed} actions executed successfully
                  </p>
                  {testResults.actions_failed > 0 && (
                    <p className="text-sm text-error-600">
                      {testResults.actions_failed} actions failed
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <h4 className="font-medium text-secondary-900">Action Results:</h4>
                  {testResults.results?.map((result: any, index: number) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-secondary-50 rounded">
                      <div className="flex items-center space-x-2">
                        {result.status === 'success' ? (
                          <CheckCircle className="h-4 w-4 text-success-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-error-500" />
                        )}
                        <span className="text-sm text-secondary-900">{result.action_name}</span>
                      </div>
                      <Badge 
                        variant={result.status === 'success' ? 'success' : 'error'} 
                        size="sm"
                      >
                        {result.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {testResults && testStatus === 'failed' && (
              <div className="mt-4 bg-error-50 border border-error-200 rounded-lg p-3">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="h-4 w-4 text-error-500" />
                  <p className="text-sm font-medium text-error-800">Test Failed</p>
                </div>
                <p className="text-sm text-error-700 mt-1">
                  {testResults.error || 'Unknown error occurred during testing'}
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Actions */}
        <div className="flex space-x-3">
          <Button variant="outline" onClick={handleClose} className="flex-1">
            Close
          </Button>
          <Button
            onClick={handleRunTest}
            loading={testStatus === 'running'}
            disabled={testStatus === 'running' || (testType !== 'mock_data' && !selectedBookingId)}
            className="flex-1"
            leftIcon={<Play className="h-4 w-4" />}
          >
            {testStatus === 'running' ? 'Testing...' : 'Run Test'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}