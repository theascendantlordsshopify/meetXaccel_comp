import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { workflowsService } from '@/services/workflows'
import { useUI } from '@/stores/uiStore'
import type {
  Workflow,
  WorkflowRequest,
  WorkflowAction,
  WorkflowActionRequest,
  WorkflowExecution,
  WorkflowTemplate,
} from '@/types'

export function useWorkflows() {
  const queryClient = useQueryClient()
  const { showSuccess, showError } = useUI()

  // Workflows
  const {
    data: workflows,
    isLoading: workflowsLoading,
    error: workflowsError,
  } = useQuery({
    queryKey: ['workflows'],
    queryFn: () => workflowsService.getWorkflows(),
  })

  const createWorkflowMutation = useMutation({
    mutationFn: (data: WorkflowRequest) => workflowsService.createWorkflow(data),
    onSuccess: () => {
      showSuccess('Workflow created', 'Your workflow has been created successfully.')
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: (error: any) => {
      showError('Failed to create workflow', error.message)
    },
  })

  const updateWorkflowMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<WorkflowRequest> }) =>
      workflowsService.updateWorkflow(id, data),
    onSuccess: () => {
      showSuccess('Workflow updated', 'Your workflow has been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: (error: any) => {
      showError('Failed to update workflow', error.message)
    },
  })

  const deleteWorkflowMutation = useMutation({
    mutationFn: (id: string) => workflowsService.deleteWorkflow(id),
    onSuccess: () => {
      showSuccess('Workflow deleted', 'The workflow has been deleted successfully.')
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: (error: any) => {
      showError('Failed to delete workflow', error.message)
    },
  })

  const testWorkflowMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) =>
      workflowsService.testWorkflow(id, data),
    onSuccess: () => {
      showSuccess('Workflow test initiated', 'Your workflow test is running in the background.')
    },
    onError: (error: any) => {
      showError('Failed to test workflow', error.message)
    },
  })

  const duplicateWorkflowMutation = useMutation({
    mutationFn: (id: string) => workflowsService.duplicateWorkflow(id),
    onSuccess: () => {
      showSuccess('Workflow duplicated', 'A copy of the workflow has been created.')
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: (error: any) => {
      showError('Failed to duplicate workflow', error.message)
    },
  })

  // Workflow Actions
  const createActionMutation = useMutation({
    mutationFn: ({ workflowId, data }: { workflowId: string; data: WorkflowActionRequest }) =>
      workflowsService.createWorkflowAction(workflowId, data),
    onSuccess: () => {
      showSuccess('Action created', 'Workflow action has been created.')
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: (error: any) => {
      showError('Failed to create action', error.message)
    },
  })

  const updateActionMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<WorkflowActionRequest> }) =>
      workflowsService.updateWorkflowAction(id, data),
    onSuccess: () => {
      showSuccess('Action updated', 'Workflow action has been updated.')
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: (error: any) => {
      showError('Failed to update action', error.message)
    },
  })

  const deleteActionMutation = useMutation({
    mutationFn: (id: string) => workflowsService.deleteWorkflowAction(id),
    onSuccess: () => {
      showSuccess('Action deleted', 'Workflow action has been deleted.')
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: (error: any) => {
      showError('Failed to delete action', error.message)
    },
  })

  // Workflow Templates
  const {
    data: templates,
    isLoading: templatesLoading,
    error: templatesError,
  } = useQuery({
    queryKey: ['workflowTemplates'],
    queryFn: () => workflowsService.getWorkflowTemplates(),
  })

  const createFromTemplateMutation = useMutation({
    mutationFn: (data: { template_id: string; name?: string }) =>
      workflowsService.createWorkflowFromTemplate(data),
    onSuccess: () => {
      showSuccess('Workflow created from template', 'Your workflow has been created from the template.')
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: (error: any) => {
      showError('Failed to create workflow from template', error.message)
    },
  })

  // Workflow Executions
  const useWorkflowExecutions = (workflowId?: string) => {
    return useQuery({
      queryKey: ['workflowExecutions', workflowId],
      queryFn: () => workflowsService.getWorkflowExecutions(workflowId),
      enabled: !!workflowId,
    })
  }

  // Performance Stats
  const useWorkflowStats = () => {
    return useQuery({
      queryKey: ['workflowStats'],
      queryFn: () => workflowsService.getWorkflowStats(),
    })
  }

  return {
    // Workflows
    workflows,
    workflowsLoading,
    workflowsError,
    createWorkflow: createWorkflowMutation.mutate,
    updateWorkflow: updateWorkflowMutation.mutate,
    deleteWorkflow: deleteWorkflowMutation.mutate,
    testWorkflow: testWorkflowMutation.mutate,
    duplicateWorkflow: duplicateWorkflowMutation.mutate,

    // Workflow Actions
    createAction: createActionMutation.mutate,
    updateAction: updateActionMutation.mutate,
    deleteAction: deleteActionMutation.mutate,

    // Templates
    templates,
    templatesLoading,
    templatesError,
    createWorkflowFromTemplate: createFromTemplateMutation.mutate,

    // Hooks
    useWorkflowExecutions,
    useWorkflowStats,

    // Loading states
    isWorkflowActionLoading:
      createWorkflowMutation.isPending ||
      updateWorkflowMutation.isPending ||
      deleteWorkflowMutation.isPending ||
      testWorkflowMutation.isPending ||
      duplicateWorkflowMutation.isPending ||
      createActionMutation.isPending ||
      updateActionMutation.isPending ||
      deleteActionMutation.isPending ||
      createFromTemplateMutation.isPending,
  }
}