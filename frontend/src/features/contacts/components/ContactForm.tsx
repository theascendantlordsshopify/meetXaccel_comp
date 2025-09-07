import React from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Checkbox } from '@/components/ui/Checkbox'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { contactSchema, type ContactFormData } from '@/types/forms'
import type { Contact } from '@/types'

interface ContactFormProps {
  contact?: Contact | null
  onSubmit: (data: ContactFormData) => void
  onCancel: () => void
  isLoading?: boolean
  submitLabel?: string
}

export function ContactForm({
  contact,
  onSubmit,
  onCancel,
  isLoading = false,
  submitLabel = 'Save Contact',
}: ContactFormProps) {
  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isDirty },
  } = useForm<ContactFormData>({
    resolver: zodResolver(contactSchema),
    defaultValues: contact ? {
      first_name: contact.first_name,
      last_name: contact.last_name || '',
      email: contact.email,
      phone: contact.phone || '',
      company: contact.company || '',
      job_title: contact.job_title || '',
      notes: contact.notes || '',
      tags: contact.tags || [],
      is_active: contact.is_active,
    } : {
      first_name: '',
      last_name: '',
      email: '',
      phone: '',
      company: '',
      job_title: '',
      notes: '',
      tags: [],
      is_active: true,
    },
  })

  const watchedValues = watch()

  return (
    <Card>
      <CardHeader title={contact ? 'Edit Contact' : 'Add New Contact'} />
      <CardContent>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          {/* Basic Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Input
              {...register('first_name')}
              label="First Name"
              placeholder="John"
              error={errors.first_name?.message}
              required
            />
            <Input
              {...register('last_name')}
              label="Last Name"
              placeholder="Doe"
              error={errors.last_name?.message}
            />
          </div>

          <Input
            {...register('email')}
            type="email"
            label="Email Address"
            placeholder="john@example.com"
            error={errors.email?.message}
            required
          />

          {/* Contact Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Input
              {...register('phone')}
              type="tel"
              label="Phone Number"
              placeholder="+1 (555) 123-4567"
              error={errors.phone?.message}
            />
            <Input
              {...register('company')}
              label="Company"
              placeholder="Acme Corp"
              error={errors.company?.message}
            />
          </div>

          <Input
            {...register('job_title')}
            label="Job Title"
            placeholder="Software Engineer"
            error={errors.job_title?.message}
          />

          {/* Notes */}
          <Textarea
            {...register('notes')}
            label="Notes"
            placeholder="Add any additional notes about this contact..."
            error={errors.notes?.message}
            rows={4}
          />

          {/* Tags */}
          <div>
            <label className="block text-sm font-medium text-secondary-700 mb-2">
              Tags
            </label>
            <Input
              placeholder="Enter tags separated by commas (e.g., vip, client, prospect)"
              onChange={(e) => {
                const tags = e.target.value.split(',').map(tag => tag.trim()).filter(Boolean)
                register('tags').onChange({ target: { value: tags } })
              }}
              defaultValue={watchedValues.tags?.join(', ') || ''}
              helpText="Separate multiple tags with commas"
            />
          </div>

          {/* Status */}
          <Checkbox
            {...register('is_active')}
            label="Active Contact"
            description="Active contacts appear in search results and can receive communications"
          />

          {/* Form Actions */}
          <div className="flex space-x-3 pt-6 border-t border-secondary-200">
            <Button
              type="button"
              variant="outline"
              onClick={onCancel}
              className="flex-1"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isLoading}
              disabled={isLoading || (!isDirty && contact)}
              className="flex-1"
            >
              {submitLabel}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}