import React, { useState } from 'react'
import { Plus, Users, Tag, Edit, Trash2, UserPlus, UserMinus } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { Avatar } from '@/components/shared/Avatar'
import { useContacts } from '@/hooks/useContacts'
import { useToggle } from '@/hooks/useToggle'
import { formatNumber } from '@/utils/helpers'
import { cn } from '@/utils/cn'
import type { ContactGroup, Contact } from '@/types'

export default function ContactGroups() {
  const [selectedGroup, setSelectedGroup] = useState<ContactGroup | null>(null)
  const [showCreateModal, { toggle: toggleCreateModal }] = useToggle()
  const [showEditModal, { toggle: toggleEditModal }] = useToggle()
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()
  const [showMembersModal, { toggle: toggleMembersModal }] = useToggle()

  const {
    contactGroups,
    contactGroupsLoading,
    contacts,
    createContactGroup,
    updateContactGroup,
    deleteContactGroup,
    addContactToGroup,
    removeContactFromGroup,
    isContactActionLoading,
  } = useContacts()

  const { data: contactsData } = contacts({})
  const allContacts = contactsData?.results || []

  const handleCreateGroup = () => {
    setSelectedGroup(null)
    toggleCreateModal()
  }

  const handleEditGroup = (group: ContactGroup) => {
    setSelectedGroup(group)
    toggleEditModal()
  }

  const handleDeleteGroup = (group: ContactGroup) => {
    setSelectedGroup(group)
    toggleDeleteDialog()
  }

  const handleViewMembers = (group: ContactGroup) => {
    setSelectedGroup(group)
    toggleMembersModal()
  }

  const confirmDelete = () => {
    if (selectedGroup) {
      deleteContactGroup(selectedGroup.id)
      setSelectedGroup(null)
      toggleDeleteDialog()
    }
  }

  if (contactGroupsLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Contact Groups"
        subtitle="Organize your contacts into groups for better management"
        breadcrumbs={[
          { label: 'Contacts', href: '/dashboard/contacts' },
          { label: 'Groups', current: true },
        ]}
        action={
          <Button
            onClick={handleCreateGroup}
            leftIcon={<Plus className="h-4 w-4" />}
          >
            Create Group
          </Button>
        }
      />

      <Container>
        {!contactGroups || contactGroups.length === 0 ? (
          <EmptyState
            icon={<Tag className="h-12 w-12" />}
            title="No contact groups yet"
            description="Create your first contact group to organize your contacts by team, project, or any other criteria"
            action={{
              label: 'Create Group',
              onClick: handleCreateGroup,
            }}
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {contactGroups.map((group) => (
              <Card
                key={group.id}
                className="group hover:shadow-medium transition-all duration-200"
                style={{ borderLeftColor: group.color, borderLeftWidth: '4px' }}
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      <div
                        className="w-10 h-10 rounded-lg flex items-center justify-center"
                        style={{ backgroundColor: `${group.color}20` }}
                      >
                        <Tag
                          className="h-5 w-5"
                          style={{ color: group.color }}
                        />
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="text-lg font-semibold text-secondary-900 group-hover:text-primary-900 transition-colors">
                          {group.name}
                        </h3>
                        {group.description && (
                          <p className="text-sm text-secondary-600 mt-1 line-clamp-2">
                            {group.description}
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleEditGroup(group)}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDeleteGroup(group)}
                        className="text-error-600 hover:text-error-700"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>

                <CardContent>
                  <div className="space-y-4">
                    {/* Contact Count */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Users className="h-4 w-4 text-secondary-400" />
                        <span className="text-sm text-secondary-600">Contacts</span>
                      </div>
                      <span className="text-lg font-semibold text-secondary-900">
                        {formatNumber(group.contact_count)}
                      </span>
                    </div>

                    {/* Recent Contacts Preview */}
                    {group.contacts && group.contacts.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-secondary-900 mb-2">Recent Members</p>
                        <div className="flex -space-x-2">
                          {group.contacts.slice(0, 4).map((contact) => (
                            <Avatar
                              key={contact.id}
                              name={contact.full_name}
                              size="sm"
                              className="ring-2 ring-white"
                            />
                          ))}
                          {group.contacts.length > 4 && (
                            <div className="w-8 h-8 rounded-full bg-secondary-100 ring-2 ring-white flex items-center justify-center">
                              <span className="text-xs font-medium text-secondary-600">
                                +{group.contacts.length - 4}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex space-x-2 pt-2 border-t border-secondary-100">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleViewMembers(group)}
                        className="flex-1"
                      >
                        <Users className="h-4 w-4 mr-2" />
                        View Members
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleEditGroup(group)}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </Container>

      {/* Create Group Modal */}
      <CreateGroupModal
        isOpen={showCreateModal}
        onClose={toggleCreateModal}
        onSubmit={(data) => {
          createContactGroup(data)
          toggleCreateModal()
        }}
        isLoading={isContactActionLoading}
        allContacts={allContacts}
      />

      {/* Edit Group Modal */}
      <EditGroupModal
        isOpen={showEditModal}
        onClose={toggleEditModal}
        group={selectedGroup}
        onSubmit={(data) => {
          if (selectedGroup) {
            updateContactGroup({ id: selectedGroup.id, data })
            toggleEditModal()
          }
        }}
        isLoading={isContactActionLoading}
        allContacts={allContacts}
      />

      {/* Group Members Modal */}
      <GroupMembersModal
        isOpen={showMembersModal}
        onClose={toggleMembersModal}
        group={selectedGroup}
        allContacts={allContacts}
        onAddContact={(contactId) => {
          if (selectedGroup) {
            addContactToGroup({ contactId, groupId: selectedGroup.id })
          }
        }}
        onRemoveContact={(contactId) => {
          if (selectedGroup) {
            removeContactFromGroup({ contactId, groupId: selectedGroup.id })
          }
        }}
        isLoading={isContactActionLoading}
      />

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        onClose={toggleDeleteDialog}
        onConfirm={confirmDelete}
        title="Delete Contact Group"
        message={`Are you sure you want to delete "${selectedGroup?.name}"? This will not delete the contacts themselves, only the group.`}
        confirmText="Delete"
        variant="danger"
      />
    </div>
  )
}

// Create Group Modal Component
function CreateGroupModal({ isOpen, onClose, onSubmit, isLoading, allContacts }: {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: any) => void
  isLoading: boolean
  allContacts: Contact[]
}) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    color: '#3b82f6',
    contact_ids: [] as string[],
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(formData)
  }

  const handleClose = () => {
    setFormData({
      name: '',
      description: '',
      color: '#3b82f6',
      contact_ids: [],
    })
    onClose()
  }

  const contactOptions = allContacts.map(contact => ({
    value: contact.id,
    label: `${contact.full_name} (${contact.email})`,
  }))

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Create Contact Group"
      size="lg"
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <Input
          label="Group Name"
          value={formData.name}
          onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
          placeholder="e.g., VIP Clients, Team Members"
          required
        />

        <Textarea
          label="Description"
          value={formData.description}
          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
          placeholder="Describe this group..."
          rows={3}
        />

        <div>
          <label className="block text-sm font-medium text-secondary-700 mb-2">
            Group Color
          </label>
          <div className="flex items-center space-x-4">
            <input
              type="color"
              value={formData.color}
              onChange={(e) => setFormData(prev => ({ ...prev, color: e.target.value }))}
              className="w-12 h-10 rounded border border-secondary-300"
            />
            <span className="text-sm text-secondary-600">
              Choose a color to identify this group
            </span>
          </div>
        </div>

        <Select
          options={contactOptions}
          value={formData.contact_ids}
          onChange={(value) => setFormData(prev => ({ ...prev, contact_ids: value as string[] }))}
          label="Add Contacts (optional)"
          placeholder="Select contacts to add to this group"
          multiple
          searchable
        />

        <div className="flex space-x-3">
          <Button type="button" variant="outline" onClick={handleClose} className="flex-1">
            Cancel
          </Button>
          <Button
            type="submit"
            loading={isLoading}
            disabled={isLoading}
            className="flex-1"
          >
            Create Group
          </Button>
        </div>
      </form>
    </Modal>
  )
}

// Edit Group Modal Component
function EditGroupModal({ isOpen, onClose, group, onSubmit, isLoading, allContacts }: {
  isOpen: boolean
  onClose: () => void
  group: ContactGroup | null
  onSubmit: (data: any) => void
  isLoading: boolean
  allContacts: Contact[]
}) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    color: '#3b82f6',
    contact_ids: [] as string[],
  })

  React.useEffect(() => {
    if (group) {
      setFormData({
        name: group.name,
        description: group.description || '',
        color: group.color,
        contact_ids: group.contacts?.map(c => c.id) || [],
      })
    }
  }, [group])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(formData)
  }

  const contactOptions = allContacts.map(contact => ({
    value: contact.id,
    label: `${contact.full_name} (${contact.email})`,
  }))

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Edit Contact Group"
      size="lg"
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <Input
          label="Group Name"
          value={formData.name}
          onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
          placeholder="e.g., VIP Clients, Team Members"
          required
        />

        <Textarea
          label="Description"
          value={formData.description}
          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
          placeholder="Describe this group..."
          rows={3}
        />

        <div>
          <label className="block text-sm font-medium text-secondary-700 mb-2">
            Group Color
          </label>
          <div className="flex items-center space-x-4">
            <input
              type="color"
              value={formData.color}
              onChange={(e) => setFormData(prev => ({ ...prev, color: e.target.value }))}
              className="w-12 h-10 rounded border border-secondary-300"
            />
            <span className="text-sm text-secondary-600">
              Choose a color to identify this group
            </span>
          </div>
        </div>

        <Select
          options={contactOptions}
          value={formData.contact_ids}
          onChange={(value) => setFormData(prev => ({ ...prev, contact_ids: value as string[] }))}
          label="Group Members"
          placeholder="Select contacts for this group"
          multiple
          searchable
        />

        <div className="flex space-x-3">
          <Button type="button" variant="outline" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button
            type="submit"
            loading={isLoading}
            disabled={isLoading}
            className="flex-1"
          >
            Save Changes
          </Button>
        </div>
      </form>
    </Modal>
  )
}

// Group Members Modal Component
function GroupMembersModal({ isOpen, onClose, group, allContacts, onAddContact, onRemoveContact, isLoading }: {
  isOpen: boolean
  onClose: () => void
  group: ContactGroup | null
  allContacts: Contact[]
  onAddContact: (contactId: string) => void
  onRemoveContact: (contactId: string) => void
  isLoading: boolean
}) {
  const [searchQuery, setSearchQuery] = useState('')

  const groupMemberIds = group?.contacts?.map(c => c.id) || []
  const availableContacts = allContacts.filter(contact => 
    !groupMemberIds.includes(contact.id) &&
    (searchQuery === '' || 
     contact.full_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
     contact.email.toLowerCase().includes(searchQuery.toLowerCase()))
  )

  const groupMembers = group?.contacts?.filter(contact =>
    searchQuery === '' || 
    contact.full_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    contact.email.toLowerCase().includes(searchQuery.toLowerCase())
  ) || []

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Manage Members: ${group?.name}`}
      size="lg"
    >
      <div className="space-y-6">
        <Input
          type="text"
          placeholder="Search contacts..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          leftIcon={<Users className="h-4 w-4" />}
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Current Members */}
          <div>
            <h4 className="font-medium text-secondary-900 mb-3">
              Current Members ({groupMembers.length})
            </h4>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {groupMembers.length === 0 ? (
                <p className="text-sm text-secondary-500">No members in this group</p>
              ) : (
                groupMembers.map((contact) => (
                  <div
                    key={contact.id}
                    className="flex items-center justify-between p-3 bg-secondary-50 rounded-lg"
                  >
                    <div className="flex items-center space-x-3">
                      <Avatar name={contact.full_name} size="sm" />
                      <div>
                        <p className="text-sm font-medium text-secondary-900">
                          {contact.full_name}
                        </p>
                        <p className="text-xs text-secondary-500">
                          {contact.email}
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => onRemoveContact(contact.id)}
                      disabled={isLoading}
                      className="text-error-600 hover:text-error-700"
                    >
                      <UserMinus className="h-4 w-4" />
                    </Button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Available Contacts */}
          <div>
            <h4 className="font-medium text-secondary-900 mb-3">
              Available Contacts ({availableContacts.length})
            </h4>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {availableContacts.length === 0 ? (
                <p className="text-sm text-secondary-500">
                  {searchQuery ? 'No contacts match your search' : 'All contacts are already in this group'}
                </p>
              ) : (
                availableContacts.map((contact) => (
                  <div
                    key={contact.id}
                    className="flex items-center justify-between p-3 bg-white border border-secondary-200 rounded-lg hover:border-secondary-300 transition-colors"
                  >
                    <div className="flex items-center space-x-3">
                      <Avatar name={contact.full_name} size="sm" />
                      <div>
                        <p className="text-sm font-medium text-secondary-900">
                          {contact.full_name}
                        </p>
                        <p className="text-xs text-secondary-500">
                          {contact.email}
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => onAddContact(contact.id)}
                      disabled={isLoading}
                      className="text-success-600 hover:text-success-700"
                    >
                      <UserPlus className="h-4 w-4" />
                    </Button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <Button onClick={onClose}>
            Done
          </Button>
        </div>
      </div>
    </Modal>
  )
}