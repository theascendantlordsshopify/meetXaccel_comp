import { apiClient } from './api'
import type {
  Contact,
  ContactGroup,
  ContactInteraction,
  ContactRequest,
  ContactGroupRequest,
  ContactListParams,
  ContactStats,
  PaginatedResponse,
} from '@/types'

export const contactsService = {
  // Contacts
  getContacts: (params?: ContactListParams): Promise<PaginatedResponse<Contact>> => {
    const queryParams = new URLSearchParams()
    if (params?.search) queryParams.append('search', params.search)
    if (params?.group) queryParams.append('group', params.group)
    if (params?.tags) queryParams.append('tags', params.tags)
    if (params?.is_active !== undefined) queryParams.append('is_active', params.is_active.toString())
    if (params?.page) queryParams.append('page', params.page.toString())
    if (params?.page_size) queryParams.append('page_size', params.page_size.toString())

    const queryString = queryParams.toString()
    return apiClient.get(`/contacts/${queryString ? `?${queryString}` : ''}`)
  },

  getContact: (id: string): Promise<Contact> =>
    apiClient.get(`/contacts/${id}/`),

  createContact: (data: ContactRequest): Promise<Contact> =>
    apiClient.post('/contacts/', data),

  updateContact: (id: string, data: Partial<ContactRequest>): Promise<Contact> =>
    apiClient.patch(`/contacts/${id}/`, data),

  deleteContact: (id: string): Promise<void> =>
    apiClient.delete(`/contacts/${id}/`),

  // Contact Groups
  getContactGroups: (): Promise<ContactGroup[]> =>
    apiClient.get('/contacts/groups/'),

  getContactGroup: (id: string): Promise<ContactGroup> =>
    apiClient.get(`/contacts/groups/${id}/`),

  createContactGroup: (data: ContactGroupRequest): Promise<ContactGroup> =>
    apiClient.post('/contacts/groups/', data),

  updateContactGroup: (id: string, data: Partial<ContactGroupRequest>): Promise<ContactGroup> =>
    apiClient.patch(`/contacts/groups/${id}/`, data),

  deleteContactGroup: (id: string): Promise<void> =>
    apiClient.delete(`/contacts/groups/${id}/`),

  // Group Management
  addContactToGroup: (contactId: string, groupId: string): Promise<{ message: string }> =>
    apiClient.post(`/contacts/${contactId}/groups/${groupId}/add/`),

  removeContactFromGroup: (contactId: string, groupId: string): Promise<{ message: string }> =>
    apiClient.post(`/contacts/${contactId}/groups/${groupId}/remove/`),

  // Contact Interactions
  getContactInteractions: (contactId: string): Promise<ContactInteraction[]> =>
    apiClient.get(`/contacts/${contactId}/interactions/`),

  addContactInteraction: (contactId: string, data: {
    interaction_type: string
    description: string
    metadata?: Record<string, any>
  }): Promise<ContactInteraction> =>
    apiClient.post(`/contacts/${contactId}/interactions/add/`, data),

  // Statistics
  getContactStats: (): Promise<ContactStats> =>
    apiClient.get('/contacts/stats/'),

  // Import/Export
  importContacts: (data: {
    csv_file: File
    skip_duplicates: boolean
    update_existing: boolean
  }): Promise<{ message: string; task_id: string }> => {
    const formData = new FormData()
    formData.append('csv_file', data.csv_file)
    formData.append('skip_duplicates', data.skip_duplicates.toString())
    formData.append('update_existing', data.update_existing.toString())

    return apiClient.post('/contacts/import/', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
  },

  exportContacts: (): Promise<Blob> =>
    apiClient.get('/contacts/export/', {
      responseType: 'blob',
    }),

  // Contact Merging
  mergeContacts: (data: {
    primary_contact_id: string
    duplicate_contact_ids: string[]
  }): Promise<{ message: string }> =>
    apiClient.post('/contacts/merge/', data),
}

export default contactsService