import React, { useState } from 'react'
import { Plus, Users, Building, Tag, Download, Upload, Search, Filter, MoreHorizontal, Edit, Trash2, Mail, Phone } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { DataTable } from '@/components/shared/DataTable'
import { Avatar } from '@/components/shared/Avatar'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { useContacts } from '@/hooks/useContacts'
import { useDebounce } from '@/hooks/useDebounce'
import { useToggle } from '@/hooks/useToggle'
import { formatDate, formatRelativeTime } from '@/utils/date'
import { formatNumber } from '@/utils/helpers'
import { cn } from '@/utils/cn'
import type { TableColumn, Contact, ContactListParams } from '@/types'

const statusOptions = [
  { value: '', label: 'All Contacts' },
  { value: 'true', label: 'Active' },
  { value: 'false', label: 'Inactive' },
]

export default function Contacts() {
  const [filters, setFilters] = useState<ContactListParams>({
    page: 1,
    page_size: 20,
  })
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null)
  const [showCreateModal, { toggle: toggleCreateModal }] = useToggle()
  const [showEditModal, { toggle: toggleEditModal }] = useToggle()
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()
  const [showImportModal, { toggle: toggleImportModal }] = useToggle()

  const debouncedSearch = useDebounce(searchQuery, 300)

  const {
    contacts,
    contactsLoading,
    contactGroups,
    contactStats,
    createContact,
    updateContact,
    deleteContact,
    exportContacts,
    importContacts,
    isContactActionLoading,
  } = useContacts()

  const { data: contactsData, isLoading } = contacts({
    ...filters,
    search: debouncedSearch || undefined,
  })

  const contactList = contactsData?.results || []
  const totalCount = contactsData?.count || 0

  const columns: TableColumn[] = [
    {
      key: 'name',
      label: 'Contact',
      render: (_, contact) => (
        <div className="flex items-center space-x-3">
          <Avatar name={contact.full_name} size="sm" />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-secondary-900 truncate">
              {contact.full_name}
            </p>
            <p className="text-xs text-secondary-500 truncate">
              {contact.email}
            </p>
          </div>
        </div>
      ),
    },
    {
      key: 'company',
      label: 'Company',
      render: (_, contact) => (
        <div className="flex items-center space-x-2">
          <Building className="h-4 w-4 text-secondary-400" />
          <span className="text-sm text-secondary-900">
            {contact.company || 'No company'}
          </span>
        </div>
      ),
    },
    {
      key: 'phone',
      label: 'Phone',
      render: (_, contact) => (
        contact.phone ? (
          <a
            href={`tel:${contact.phone}`}
            className="flex items-center space-x-2 text-primary-600 hover:text-primary-700"
          >
            <Phone className="h-4 w-4" />
            <span className="text-sm">{contact.phone}</span>
          </a>
        ) : (
          <span className="text-sm text-secondary-500">No phone</span>
        )
      ),
    },
    {
      key: 'tags',
      label: 'Tags',
      render: (_, contact) => (
        <div className="flex flex-wrap gap-1">
          {contact.tags?.slice(0, 2).map((tag, index) => (
            <Badge key={index} variant="secondary" size="sm">
              {tag}
            </Badge>
          ))}
          {contact.tags && contact.tags.length > 2 && (
            <Badge variant="secondary" size="sm">
              +{contact.tags.length - 2}
            </Badge>
          )}
        </div>
      ),
    },
    {
      key: 'total_bookings',
      label: 'Bookings',
      render: (_, contact) => (
        <div className="text-center">
          <span className="text-sm font-medium text-secondary-900">
            {formatNumber(contact.total_bookings)}
          </span>
          {contact.last_booking_date && (
            <p className="text-xs text-secondary-500">
              Last: {formatRelativeTime(contact.last_booking_date)}
            </p>
          )}
        </div>
      ),
    },
    {
      key: 'created_at',
      label: 'Added',
      render: (_, contact) => (
        <span className="text-sm text-secondary-600">
          {formatRelativeTime(contact.created_at)}
        </span>
      ),
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (_, contact) => (
        <div className="flex items-center space-x-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => window.open(`mailto:${contact.email}`, '_blank')}
            title="Send email"
          >
            <Mail className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleEditContact(contact)}
            title="Edit contact"
          >
            <Edit className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleDeleteContact(contact)}
            className="text-error-600 hover:text-error-700"
            title="Delete contact"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ]

  const handleFilterChange = (key: string, value: any) => {
    setFilters(prev => ({
      ...prev,
      [key]: value,
      page: 1,
    }))
  }

  const handlePageChange = (page: number) => {
    setFilters(prev => ({ ...prev, page }))
  }

  const handleCreateContact = () => {
    setSelectedContact(null)
    toggleCreateModal()
  }

  const handleEditContact = (contact: Contact) => {
    setSelectedContact(contact)
    toggleEditModal()
  }

  const handleDeleteContact = (contact: Contact) => {
    setSelectedContact(contact)
    toggleDeleteDialog()
  }

  const confirmDelete = () => {
    if (selectedContact) {
      deleteContact(selectedContact.id)
      setSelectedContact(null)
      toggleDeleteDialog()
    }
  }

  const handleExport = () => {
    exportContacts()
  }

  const handleImport = () => {
    toggleImportModal()
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Contacts"
        subtitle="Manage your contact list and organize relationships"
        action={
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleImport}
              leftIcon={<Upload className="h-4 w-4" />}
            >
              Import
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleExport}
              leftIcon={<Download className="h-4 w-4" />}
            >
              Export
            </Button>
            <Button
              onClick={handleCreateContact}
              leftIcon={<Plus className="h-4 w-4" />}
            >
              Add Contact
            </Button>
          </div>
        }
      />

      <Container>
        {/* Stats Overview */}
        {contactStats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-secondary-600">Total Contacts</p>
                    <p className="text-2xl font-bold text-secondary-900">
                      {formatNumber(contactStats.total_contacts)}
                    </p>
                  </div>
                  <div className="p-3 bg-primary-100 rounded-lg">
                    <Users className="h-6 w-6 text-primary-600" />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-secondary-600">Active</p>
                    <p className="text-2xl font-bold text-secondary-900">
                      {formatNumber(contactStats.active_contacts)}
                    </p>
                  </div>
                  <div className="p-3 bg-success-100 rounded-lg">
                    <Users className="h-6 w-6 text-success-600" />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-secondary-600">Groups</p>
                    <p className="text-2xl font-bold text-secondary-900">
                      {formatNumber(contactStats.total_groups)}
                    </p>
                  </div>
                  <div className="p-3 bg-warning-100 rounded-lg">
                    <Tag className="h-6 w-6 text-warning-600" />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-secondary-600">This Month</p>
                    <p className="text-2xl font-bold text-secondary-900">
                      {formatNumber(contactStats.booking_frequency?.this_month || 0)}
                    </p>
                  </div>
                  <div className="p-3 bg-secondary-100 rounded-lg">
                    <Building className="h-6 w-6 text-secondary-600" />
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Filters and Search */}
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex items-center space-x-4">
              <div className="flex-1">
                <Input
                  type="text"
                  placeholder="Search contacts..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  leftIcon={<Search className="h-4 w-4" />}
                  className="max-w-md"
                />
              </div>

              <Select
                options={statusOptions}
                value={filters.is_active?.toString() || ''}
                onChange={(value) => handleFilterChange('is_active', value === '' ? undefined : value === 'true')}
                placeholder="Filter by status"
                className="w-48"
              />

              {contactGroups && contactGroups.length > 0 && (
                <Select
                  options={[
                    { value: '', label: 'All Groups' },
                    ...contactGroups.map(group => ({
                      value: group.id,
                      label: group.name,
                    }))
                  ]}
                  value={filters.group || ''}
                  onChange={(value) => handleFilterChange('group', value || undefined)}
                  placeholder="Filter by group"
                  className="w-48"
                />
              )}

              <Button
                variant="outline"
                size="sm"
                leftIcon={<Filter className="h-4 w-4" />}
              >
                More Filters
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Contacts Table */}
        {isLoading ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <LoadingSpinner size="lg" />
          </div>
        ) : contactList.length === 0 ? (
          <EmptyState
            icon={<Users className="h-12 w-12" />}
            title="No contacts yet"
            description="Start building your contact list by adding your first contact or importing from a CSV file"
            action={{
              label: 'Add Contact',
              onClick: handleCreateContact,
            }}
          />
        ) : (
          <Card>
            <CardHeader title="All Contacts" />
            <CardContent>
              <DataTable
                columns={columns}
                data={contactList}
                loading={isLoading}
                emptyMessage="No contacts found"
                pagination={{
                  page: filters.page || 1,
                  pageSize: filters.page_size || 20,
                  total: totalCount,
                }}
                onPageChange={handlePageChange}
                searchable={false} // We handle search separately
              />
            </CardContent>
          </Card>
        )}
      </Container>

      {/* Create Contact Modal */}
      <CreateContactModal
        isOpen={showCreateModal}
        onClose={toggleCreateModal}
        onSubmit={(data) => {
          createContact(data)
          toggleCreateModal()
        }}
        isLoading={isContactActionLoading}
      />

      {/* Edit Contact Modal */}
      <EditContactModal
        isOpen={showEditModal}
        onClose={toggleEditModal}
        contact={selectedContact}
        onSubmit={(data) => {
          if (selectedContact) {
            updateContact({ id: selectedContact.id, data })
            toggleEditModal()
          }
        }}
        isLoading={isContactActionLoading}
      />

      {/* Import Modal */}
      <ImportContactsModal
        isOpen={showImportModal}
        onClose={toggleImportModal}
        onSubmit={(data) => {
          importContacts(data)
          toggleImportModal()
        }}
        isLoading={isContactActionLoading}
      />

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        onClose={toggleDeleteDialog}
        onConfirm={confirmDelete}
        title="Delete Contact"
        message={`Are you sure you want to delete ${selectedContact?.full_name}? This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
      />
    </div>
  )
}

// Create Contact Modal Component
function CreateContactModal({ isOpen, onClose, onSubmit, isLoading }: {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: any) => void
  isLoading: boolean
}) {
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    email: '',
    phone: '',
    company: '',
    job_title: '',
    notes: '',
    tags: [] as string[],
    is_active: true,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(formData)
  }

  const handleClose = () => {
    setFormData({
      first_name: '',
      last_name: '',
      email: '',
      phone: '',
      company: '',
      job_title: '',
      notes: '',
      tags: [],
      is_active: true,
    })
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Add New Contact"
      size="lg"
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Input
            label="First Name"
            value={formData.first_name}
            onChange={(e) => setFormData(prev => ({ ...prev, first_name: e.target.value }))}
            placeholder="John"
            required
          />
          <Input
            label="Last Name"
            value={formData.last_name}
            onChange={(e) => setFormData(prev => ({ ...prev, last_name: e.target.value }))}
            placeholder="Doe"
            required
          />
        </div>

        <Input
          type="email"
          label="Email Address"
          value={formData.email}
          onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
          placeholder="john@example.com"
          required
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Input
            type="tel"
            label="Phone Number"
            value={formData.phone}
            onChange={(e) => setFormData(prev => ({ ...prev, phone: e.target.value }))}
            placeholder="+1 (555) 123-4567"
          />
          <Input
            label="Company"
            value={formData.company}
            onChange={(e) => setFormData(prev => ({ ...prev, company: e.target.value }))}
            placeholder="Acme Corp"
          />
        </div>

        <Input
          label="Job Title"
          value={formData.job_title}
          onChange={(e) => setFormData(prev => ({ ...prev, job_title: e.target.value }))}
          placeholder="Software Engineer"
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
            Add Contact
          </Button>
        </div>
      </form>
    </Modal>
  )
}

// Edit Contact Modal Component
function EditContactModal({ isOpen, onClose, contact, onSubmit, isLoading }: {
  isOpen: boolean
  onClose: () => void
  contact: Contact | null
  onSubmit: (data: any) => void
  isLoading: boolean
}) {
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    email: '',
    phone: '',
    company: '',
    job_title: '',
    notes: '',
    tags: [] as string[],
    is_active: true,
  })

  React.useEffect(() => {
    if (contact) {
      setFormData({
        first_name: contact.first_name,
        last_name: contact.last_name || '',
        email: contact.email,
        phone: contact.phone || '',
        company: contact.company || '',
        job_title: contact.job_title || '',
        notes: contact.notes || '',
        tags: contact.tags || [],
        is_active: contact.is_active,
      })
    }
  }, [contact])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(formData)
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Edit Contact"
      size="lg"
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Input
            label="First Name"
            value={formData.first_name}
            onChange={(e) => setFormData(prev => ({ ...prev, first_name: e.target.value }))}
            placeholder="John"
            required
          />
          <Input
            label="Last Name"
            value={formData.last_name}
            onChange={(e) => setFormData(prev => ({ ...prev, last_name: e.target.value }))}
            placeholder="Doe"
            required
          />
        </div>

        <Input
          type="email"
          label="Email Address"
          value={formData.email}
          onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
          placeholder="john@example.com"
          required
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Input
            type="tel"
            label="Phone Number"
            value={formData.phone}
            onChange={(e) => setFormData(prev => ({ ...prev, phone: e.target.value }))}
            placeholder="+1 (555) 123-4567"
          />
          <Input
            label="Company"
            value={formData.company}
            onChange={(e) => setFormData(prev => ({ ...prev, company: e.target.value }))}
            placeholder="Acme Corp"
          />
        </div>

        <Input
          label="Job Title"
          value={formData.job_title}
          onChange={(e) => setFormData(prev => ({ ...prev, job_title: e.target.value }))}
          placeholder="Software Engineer"
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

// Import Contacts Modal Component
function ImportContactsModal({ isOpen, onClose, onSubmit, isLoading }: {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: any) => void
  isLoading: boolean
}) {
  const [file, setFile] = useState<File | null>(null)
  const [skipDuplicates, setSkipDuplicates] = useState(true)
  const [updateExisting, setUpdateExisting] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (file) {
      onSubmit({
        csv_file: file,
        skip_duplicates: skipDuplicates,
        update_existing: updateExisting,
      })
    }
  }

  const handleClose = () => {
    setFile(null)
    setSkipDuplicates(true)
    setUpdateExisting(false)
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Import Contacts"
      size="md"
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label className="block text-sm font-medium text-secondary-700 mb-2">
            CSV File
          </label>
          <input
            type="file"
            accept=".csv"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            className="block w-full text-sm text-secondary-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-primary-50 file:text-primary-700 hover:file:bg-primary-100"
            required
          />
          <p className="text-xs text-secondary-500 mt-1">
            Upload a CSV file with columns: first_name, last_name, email, phone, company, job_title, notes, tags
          </p>
        </div>

        <div className="space-y-4">
          <div className="flex items-center">
            <input
              type="checkbox"
              id="skipDuplicates"
              checked={skipDuplicates}
              onChange={(e) => setSkipDuplicates(e.target.checked)}
              className="rounded border-secondary-300 text-primary-600 focus:ring-primary-500"
            />
            <label htmlFor="skipDuplicates" className="ml-2 text-sm text-secondary-700">
              Skip duplicate contacts
            </label>
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              id="updateExisting"
              checked={updateExisting}
              onChange={(e) => setUpdateExisting(e.target.checked)}
              className="rounded border-secondary-300 text-primary-600 focus:ring-primary-500"
            />
            <label htmlFor="updateExisting" className="ml-2 text-sm text-secondary-700">
              Update existing contacts
            </label>
          </div>
        </div>

        <div className="bg-info-50 border border-info-200 rounded-lg p-4">
          <h4 className="font-medium text-info-800 mb-2">Import Guidelines</h4>
          <ul className="text-sm text-info-700 space-y-1 list-disc list-inside">
            <li>CSV file should have headers in the first row</li>
            <li>Email column is required for all contacts</li>
            <li>Tags should be comma-separated in a single column</li>
            <li>Duplicate detection is based on email address</li>
          </ul>
        </div>

        <div className="flex space-x-3">
          <Button type="button" variant="outline" onClick={handleClose} className="flex-1">
            Cancel
          </Button>
          <Button
            type="submit"
            loading={isLoading}
            disabled={isLoading || !file}
            className="flex-1"
          >
            Import Contacts
          </Button>
        </div>
      </form>
    </Modal>
  )
}