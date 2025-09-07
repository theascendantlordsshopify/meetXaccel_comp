import { apiClient } from './api'
import type {
  Workflow,
  WorkflowRequest,
  WorkflowAction,
  WorkflowActionRequest,
  WorkflowExecution,
  WorkflowTemplate,
} from '@/types'

export const workflowsService = {
  // Workflows
  getWorkflows: (): Promise<Workflow[]> =>
    apiClient.get('/workflows/'),

  getWorkflow: (id: string): Promise<Workflow> =>
    apiClient.get(`/workflows/${id}/`),

  createWorkflow: (data: WorkflowRequest): Promise<Workflow> =>
    apiClient.post('/workflows/', data),

  updateWorkflow: (id: string, data: Partial<WorkflowRequest>): Promise<Workflow> =>
    apiClient.patch(`/workflows/${id}/`, data),

  deleteWorkflow: (id: string): Promise<void> =>
    apiClient.delete(`/workflows/${id}/`),

  testWorkflow: (id: string, data: any): Promise<any> =>
    apiClient.post(`/workflows/${id}/test/`, data),

  validateWorkflow: (id: string): Promise<any> =>
    apiClient.post(`/workflows/${id}/validate/`),

  duplicateWorkflow: (id: string): Promise<Workflow> =>
    apiClient.post(`/workflows/${id}/duplicate/`),

  // Workflow Actions
  getWorkflowActions: (workflowId: string): Promise<WorkflowAction[]> =>
    apiClient.get(`/workflows/${workflowId}/actions/`),

  createWorkflowAction: (workflowId: string, data: WorkflowActionRequest): Promise<WorkflowAction> =>
    apiClient.post(`/workflows/${workflowId}/actions/`, data),

  updateWorkflowAction: (id: string, data: Partial<WorkflowActionRequest>): Promise<WorkflowAction> =>
    apiClient.patch(`/workflows/actions/${id}/`, data),

  deleteWorkflowAction: (id: string): Promise<void> =>
    apiClient.delete(`/workflows/actions/${id}/`),

  // Workflow Executions
  getWorkflowExecutions: (workflowId?: string): Promise<WorkflowExecution[]> => {
    const url = workflowId ? `/workflows/executions/?workflow=${workflowId}` : '/workflows/executions/'
    return apiClient.get(url)
  },

  getWorkflowExecutionSummary: (id: string): Promise<any> =>
    apiClient.get(`/workflows/${id}/execution-summary/`),

  // Workflow Templates
  getWorkflowTemplates: (): Promise<WorkflowTemplate[]> =>
    apiClient.get('/workflows/templates/'),

  createWorkflowFromTemplate: (data: { template_id: string; name?: string }): Promise<Workflow> =>
    apiClient.post('/workflows/templates/create-from/', data),

  // Performance and Analytics
  getWorkflowStats: (): Promise<any> =>
    apiClient.get('/workflows/performance-stats/'),

  bulkTestWorkflows: (data: { workflow_ids: string[]; test_type: string }): Promise<any> =>
    apiClient.post('/workflows/bulk-test/', data),
}

export default workflowsService