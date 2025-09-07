import React, { useState } from 'react'
import { Users, ArrowRight, Check, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Modal } from '@/components/ui/Modal'
import { Avatar } from '@/components/shared/Avatar'
import { Badge } from '@/components/ui/Badge'
import { useContacts } from '@/hooks/useContacts'
import { formatRelativeTime } from '@/utils/date'
import type { Contact } from '@/types'

interface ContactMergeProps {
  isOpen: boolean
  onClose: () => void
  contacts: Contact[]
}

export function ContactMerge({ isOpen, onClose, contacts }: ContactMergeProps) {
  const [primaryContact, setPrimaryContact] = useState<Contact | null>(null)
  const [duplicateContacts, setDuplicateContacts] = useState<Contact[]>([])
  const { mergeContacts, isContactActionLoading } = useContacts()

  React.useEffect(() => {
    if (contacts.length > 0) {
      // Auto-select the contact with the most bookings as primary
      const sortedContacts = [...contacts].sort((a, b) => b.total_bookings - a.total_bookings)
      setPrimaryContact(sortedContacts[0])
      setDuplicateContacts(sortedContacts.slice(1))
    }
  }, [contacts])

  const handleMerge = async () => {
    if (!primaryContact || duplicateContacts.length === 0) return

    try {
      await mergeContacts({
        primary_contact_id: primaryContact.id,
        duplicate_contact_ids: duplicateContacts.map(c => c.id),
      })
      onClose()
    } catch (error) {
      console.error('Merge failed:', error)
    }
  }

  const toggleDuplicateSelection = (contact: Contact) => {
    if (duplicateContacts.find(c => c.id === contact.id)) {
      setDuplicateContacts(prev => prev.filter(c => c.id !== contact.id))
    } else {
      setDuplicateContacts(prev => [...prev, contact])
    }
  }

  const setPrimary = (contact: Contact) => {
    if (primaryContact) {
      setDuplicateContacts(prev => [...prev, primaryContact])
    }
    setPrimaryContact(contact)
    setDuplicateContacts(prev => prev.filter(c => c.id !== contact.id))
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Merge Duplicate Contacts"
      size="xl"
    >
      <div className="space-y-6">
        <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
          <h4 className="font-medium text-warning-800 mb-2">Important</h4>
          <p className="text-sm text-warning-700">
            Merging contacts will combine all data into the primary contact and permanently delete the duplicates. 
            This action cannot be undone.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Primary Contact */}
          <div>
            <h4 className="font-medium text-secondary-900 mb-3">
              Primary Contact (Keep)
            </h4>
            {primaryContact && (
              <Card className="border-success-200 bg-success-50">
                <CardContent className="p-4">
                  <div className="flex items-center space-x-3 mb-3">
                    <Avatar name={primaryContact.full_name} size="sm" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-secondary-900">
                        {primaryContact.full_name}
                      </p>
                      <p className="text-xs text-secondary-600">
                        {primaryContact.email}
                      </p>
                    </div>
                    <Check className="h-4 w-4 text-success-500" />
                  </div>
                  
                  <div className="space-y-2 text-xs text-secondary-600">
                    {primaryContact.company && (
                      <p>Company: {primaryContact.company}</p>
                    )}
                    {primaryContact.phone && (
                      <p>Phone: {primaryContact.phone}</p>
                    )}
                    <p>Bookings: {primaryContact.total_bookings}</p>
                    <p>Added: {formatRelativeTime(primaryContact.created_at)}</p>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Arrow */}
          <div className="flex items-center justify-center">
            <div className="flex flex-col items-center space-y-2">
              <ArrowRight className="h-6 w-6 text-secondary-400" />
              <span className="text-xs text-secondary-500">Merge into</span>
            </div>
          </div>

          {/* Duplicate Contacts */}
          <div>
            <h4 className="font-medium text-secondary-900 mb-3">
              Duplicates to Merge ({duplicateContacts.length})
            </h4>
            <div className="space-y-3 max-h-64 overflow-y-auto">
              {contacts.filter(c => c.id !== primaryContact?.id).map((contact) => {
                const isSelected = duplicateContacts.find(c => c.id === contact.id)
                
                return (
                  <Card
                    key={contact.id}
                    className={`cursor-pointer transition-colors ${
                      isSelected 
                        ? 'border-error-200 bg-error-50' 
                        : 'border-secondary-200 hover:border-secondary-300'
                    }`}
                    onClick={() => toggleDuplicateSelection(contact)}
                  >
                    <CardContent className="p-3">
                      <div className="flex items-center space-x-3">
                        <Avatar name={contact.full_name} size="sm" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-secondary-900">
                            {contact.full_name}
                          </p>
                          <p className="text-xs text-secondary-600">
                            {contact.email}
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          {isSelected ? (
                            <X className="h-4 w-4 text-error-500" />
                          ) : (
                            <div className="w-4 h-4 border border-secondary-300 rounded" />
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              setPrimary(contact)
                            }}
                            className="text-xs"
                          >
                            Make Primary
                          </Button>
                        </div>
                      </div>
                      
                      <div className="mt-2 text-xs text-secondary-600">
                        <p>Bookings: {contact.total_bookings}</p>
                        <p>Added: {formatRelativeTime(contact.created_at)}</p>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        </div>

        {/* Merge Preview */}
        {primaryContact && duplicateContacts.length > 0 && (
          <Card className="bg-info-50 border-info-200">
            <CardContent className="p-4">
              <h4 className="font-medium text-info-800 mb-2">Merge Preview</h4>
              <div className="text-sm text-info-700 space-y-1">
                <p>• Primary contact: <strong>{primaryContact.full_name}</strong> will be kept</p>
                <p>• {duplicateContacts.length} duplicate contact(s) will be deleted</p>
                <p>• All booking history and interactions will be preserved</p>
                <p>• Tags and notes will be combined</p>
                <p>• Group memberships will be merged</p>
              </div>
            </CardContent>
          </Card>
        )}

        <div className="flex space-x-3">
          <Button variant="outline" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button
            onClick={handleMerge}
            loading={isContactActionLoading}
            disabled={isContactActionLoading || !primaryContact || duplicateContacts.length === 0}
            className="flex-1"
            variant="danger"
          >
            Merge {duplicateContacts.length} Contact{duplicateContacts.length !== 1 ? 's' : ''}
          </Button>
        </div>
      </div>
    </Modal>
  )
}