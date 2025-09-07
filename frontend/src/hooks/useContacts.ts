import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { contactsService } from '@/services/contacts'
import { useUI } from '@/stores/uiStore'
import type {
  Contact,
  ContactGroup,
  ContactInteraction,
  ContactRequest,
  ContactGroupRequest,
  ContactListParams,
  ContactStats,
} from '@/types'

export function useContacts() {
  const queryClient = useQueryClient()
  const { showSuccess, showError } = useUI()

  // Contacts
  const useContactsList = (params?: ContactListParams) => {
    return useQuery({
      queryKey: ['contacts', params],
      queryFn: () => contactsService.getContacts(params),
    })
  }

  const useContact = (id: string) => {
    return useQuery({
      queryKey: ['contact', id],
      queryFn: () => contactsService.getContact(id),
      enabled: !!id,
    })
  }

  const createContactMutation = useMutation({
    mutationFn: (data: ContactRequest) => contactsService.createContact(data),
    onSuccess: () => {
      showSuccess('Contact created', 'The contact has been added successfully.')
      queryClient.invalidateQueries({ queryKey: ['contacts'] })
      queryClient.invalidateQueries({ queryKey: ['contactStats'] })
    },
    onError: (error: any) => {
      showError('Failed to create contact', error.message)
    },
  })

  const updateContactMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ContactRequest> }) =>
      contactsService.updateContact(id, data),
    onSuccess: () => {
      showSuccess('Contact updated', 'The contact has been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['contacts'] })
      queryClient.invalidateQueries({ queryKey: ['contact'] })
    },
    onError: (error: any) => {
      showError('Failed to update contact', error.message)
    },
  })

  const deleteContactMutation = useMutation({
    mutationFn: (id: string) => contactsService.deleteContact(id),
    onSuccess: () => {
      showSuccess('Contact deleted', 'The contact has been deleted successfully.')
      queryClient.invalidateQueries({ queryKey: ['contacts'] })
      queryClient.invalidateQueries({ queryKey: ['contactStats'] })
    },
    onError: (error: any) => {
      showError('Failed to delete contact', error.message)
    },
  })

  // Contact Groups
  const {
    data: contactGroups,
    isLoading: contactGroupsLoading,
    error: contactGroupsError,
  } = useQuery({
    queryKey: ['contactGroups'],
    queryFn: () => contactsService.getContactGroups(),
  })

  const createContactGroupMutation = useMutation({
    mutationFn: (data: ContactGroupRequest) => contactsService.createContactGroup(data),
    onSuccess: () => {
      showSuccess('Group created', 'The contact group has been created successfully.')
      queryClient.invalidateQueries({ queryKey: ['contactGroups'] })
    },
    onError: (error: any) => {
      showError('Failed to create group', error.message)
    },
  })

  const updateContactGroupMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ContactGroupRequest> }) =>
      contactsService.updateContactGroup(id, data),
    onSuccess: () => {
      showSuccess('Group updated', 'The contact group has been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['contactGroups'] })
    },
    onError: (error: any) => {
      showError('Failed to update group', error.message)
    },
  })

  const deleteContactGroupMutation = useMutation({
    mutationFn: (id: string) => contactsService.deleteContactGroup(id),
    onSuccess: () => {
      showSuccess('Group deleted', 'The contact group has been deleted successfully.')
      queryClient.invalidateQueries({ queryKey: ['contactGroups'] })
    },
    onError: (error: any) => {
      showError('Failed to delete group', error.message)
    },
  })

  // Group Management
  const addContactToGroupMutation = useMutation({
    mutationFn: ({ contactId, groupId }: { contactId: string; groupId: string }) =>
      contactsService.addContactToGroup(contactId, groupId),
    onSuccess: () => {
      showSuccess('Contact added to group', 'The contact has been added to the group.')
      queryClient.invalidateQueries({ queryKey: ['contactGroups'] })
      queryClient.invalidateQueries({ queryKey: ['contacts'] })
    },
    onError: (error: any) => {
      showError('Failed to add contact to group', error.message)
    },
  })

  const removeContactFromGroupMutation = useMutation({
    mutationFn: ({ contactId, groupId }: { contactId: string; groupId: string }) =>
      contactsService.removeContactFromGroup(contactId, groupId),
    onSuccess: () => {
      showSuccess('Contact removed from group', 'The contact has been removed from the group.')
      queryClient.invalidateQueries({ queryKey: ['contactGroups'] })
      queryClient.invalidateQueries({ queryKey: ['contacts'] })
    },
    onError: (error: any) => {
      showError('Failed to remove contact from group', error.message)
    },
  })

  // Contact Interactions
  const useContactInteractions = (contactId: string) => {
    return useQuery({
      queryKey: ['contactInteractions', contactId],
      queryFn: () => contactsService.getContactInteractions(contactId),
      enabled: !!contactId,
    })
  }

  const addContactInteractionMutation = useMutation({
    mutationFn: ({ contactId, data }: { contactId: string; data: any }) =>
      contactsService.addContactInteraction(contactId, data),
    onSuccess: () => {
      showSuccess('Interaction added', 'The interaction has been recorded.')
      queryClient.invalidateQueries({ queryKey: ['contactInteractions'] })
    },
    onError: (error: any) => {
      showError('Failed to add interaction', error.message)
    },
  })

  // Import/Export
  const importContactsMutation = useMutation({
    mutationFn: (data: { csv_file: File; skip_duplicates: boolean; update_existing: boolean }) =>
      contactsService.importContacts(data),
    onSuccess: () => {
      showSuccess('Import started', 'Your contacts are being imported in the background.')
      queryClient.invalidateQueries({ queryKey: ['contacts'] })
      queryClient.invalidateQueries({ queryKey: ['contactStats'] })
    },
    onError: (error: any) => {
      showError('Import failed', error.message)
    },
  })

  const exportContactsMutation = useMutation({
    mutationFn: () => contactsService.exportContacts(),
    onSuccess: () => {
      showSuccess('Export started', 'Your contacts export will download shortly.')
    },
    onError: (error: any) => {
      showError('Export failed', error.message)
    },
  })

  // Contact Merging
  const mergeContactsMutation = useMutation({
    mutationFn: (data: { primary_contact_id: string; duplicate_contact_ids: string[] }) =>
      contactsService.mergeContacts(data),
    onSuccess: () => {
      showSuccess('Contacts merged', 'The contacts have been merged successfully.')
      queryClient.invalidateQueries({ queryKey: ['contacts'] })
      queryClient.invalidateQueries({ queryKey: ['contactStats'] })
    },
    onError: (error: any) => {
      showError('Failed to merge contacts', error.message)
    },
  })

  // Statistics
  const {
    data: contactStats,
    isLoading: contactStatsLoading,
    error: contactStatsError,
  } = useQuery({
    queryKey: ['contactStats'],
    queryFn: () => contactsService.getContactStats(),
  })

  return {
    // Contacts
    contacts: useContactsList,
    useContact,
    createContact: createContactMutation.mutate,
    updateContact: updateContactMutation.mutate,
    deleteContact: deleteContactMutation.mutate,

    // Contact Groups
    contactGroups,
    contactGroupsLoading,
    contactGroupsError,
    createContactGroup: createContactGroupMutation.mutate,
    updateContactGroup: updateContactGroupMutation.mutate,
    deleteContactGroup: deleteContactGroupMutation.mutate,

    // Group Management
    addContactToGroup: addContactToGroupMutation.mutate,
    removeContactFromGroup: removeContactFromGroupMutation.mutate,

    // Interactions
    useContactInteractions,
    addContactInteraction: addContactInteractionMutation.mutate,

    // Import/Export
    importContacts: importContactsMutation.mutate,
    exportContacts: exportContactsMutation.mutate,

    // Merging
    mergeContacts: mergeContactsMutation.mutate,

    // Statistics
    contactStats,
    contactStatsLoading,
    contactStatsError,

    // Loading states
    isContactActionLoading:
      createContactMutation.isPending ||
      updateContactMutation.isPending ||
      deleteContactMutation.isPending ||
      createContactGroupMutation.isPending ||
      updateContactGroupMutation.isPending ||
      deleteContactGroupMutation.isPending ||
      addContactToGroupMutation.isPending ||
      removeContactFromGroupMutation.isPending ||
      addContactInteractionMutation.isPending ||
      importContactsMutation.isPending ||
      exportContactsMutation.isPending ||
      mergeContactsMutation.isPending,
  }
}