import React, { useState } from 'react'
import { TestTube, Send, CheckCircle, XCircle, Clock } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Textarea } from '@/components/ui/Textarea'
import { Badge } from '@/components/ui/Badge'
import { Modal } from '@/components/ui/Modal'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'

interface WebhookTesterProps {
  isOpen: boolean
  onClose: () => void
  webhookUrl: string
  webhookName: string
  onTest: () => void
}

export function WebhookTester({ isOpen, onClose, webhookUrl, webhookName, onTest }: WebhookTesterProps) {
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle')
  const [testResult, setTestResult] = useState<any>(null)

  const samplePayload = {
    event: 'booking_created',
    timestamp: new Date().toISOString(),
    data: {
      booking_id: 'test-booking-123',
      event_type_name: 'Discovery Call',
      invitee_name: 'John Doe',
      invitee_email: 'john.doe@example.com',
      organizer_email: 'organizer@example.com',
      start_time: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      end_time: new Date(Date.now() + 24 * 60 * 60 * 1000 + 30 * 60 * 1000).toISOString(),
      duration_minutes: 30,
      status: 'confirmed',
    },
  }

  const handleTest = async () => {
    setTestStatus('testing')
    
    try {
      // Call the test function
      await onTest()
      
      // Simulate test result for demo
      setTimeout(() => {
        setTestStatus('success')
        setTestResult({
          status_code: 200,
          response_time: '245ms',
          response_body: '{"success": true, "message": "Webhook received successfully"}',
        })
      }, 2000)
    } catch (error) {
      setTestStatus('error')
      setTestResult({
        status_code: 500,
        error: 'Connection timeout',
        response_time: '30000ms',
      })
    }
  }

  const getStatusIcon = () => {
    switch (testStatus) {
      case 'testing':
        return <Clock className="h-5 w-5 text-warning-500" />
      case 'success':
        return <CheckCircle className="h-5 w-5 text-success-500" />
      case 'error':
        return <XCircle className="h-5 w-5 text-error-500" />
      default:
        return <TestTube className="h-5 w-5 text-secondary-500" />
    }
  }

  const getStatusColor = () => {
    switch (testStatus) {
      case 'testing':
        return 'warning'
      case 'success':
        return 'success'
      case 'error':
        return 'error'
      default:
        return 'secondary'
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Test Webhook"
      size="lg"
    >
      <div className="space-y-6">
        <div className="flex items-center space-x-3">
          <TestTube className="h-8 w-8 text-primary-600" />
          <div>
            <h3 className="text-lg font-semibold text-secondary-900">
              {webhookName}
            </h3>
            <p className="text-sm text-secondary-600 truncate">
              {webhookUrl}
            </p>
          </div>
        </div>

        {/* Test Status */}
        <Card>
          <CardHeader title="Test Status" />
          <CardContent>
            <div className="flex items-center space-x-3">
              {getStatusIcon()}
              <div className="flex-1">
                <p className="text-sm font-medium text-secondary-900">
                  {testStatus === 'idle' && 'Ready to test'}
                  {testStatus === 'testing' && 'Sending test webhook...'}
                  {testStatus === 'success' && 'Test successful!'}
                  {testStatus === 'error' && 'Test failed'}
                </p>
                {testResult && (
                  <p className="text-xs text-secondary-500">
                    Response time: {testResult.response_time}
                  </p>
                )}
              </div>
              <Badge variant={getStatusColor()} size="sm">
                {testStatus}
              </Badge>
            </div>

            {testResult && (
              <div className="mt-4 space-y-3">
                <div className="bg-secondary-50 p-3 rounded-lg">
                  <p className="text-sm font-medium text-secondary-900 mb-1">
                    Status Code: {testResult.status_code}
                  </p>
                  {testResult.response_body && (
                    <pre className="text-xs text-secondary-600 whitespace-pre-wrap">
                      {testResult.response_body}
                    </pre>
                  )}
                  {testResult.error && (
                    <p className="text-xs text-error-600">
                      Error: {testResult.error}
                    </p>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Sample Payload */}
        <Card>
          <CardHeader title="Sample Payload" />
          <CardContent>
            <Textarea
              value={JSON.stringify(samplePayload, null, 2)}
              readOnly
              rows={12}
              className="font-mono text-xs"
            />
            <p className="text-xs text-secondary-500 mt-2">
              This is the payload structure that will be sent to your webhook endpoint.
            </p>
          </CardContent>
        </Card>

        <div className="flex space-x-3">
          <Button variant="outline" onClick={onClose} className="flex-1">
            Close
          </Button>
          <Button
            onClick={handleTest}
            loading={testStatus === 'testing'}
            disabled={testStatus === 'testing'}
            className="flex-1"
            leftIcon={<Send className="h-4 w-4" />}
          >
            Send Test
          </Button>
        </div>
      </div>
    </Modal>
  )
}