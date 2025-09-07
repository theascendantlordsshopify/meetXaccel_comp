import React from 'react'
import { FormSection } from './FormSection'
import { Button } from '@/components/ui/Button'
import type { FormSection as FormSectionType } from '@/types/common'

interface DynamicFormProps {
  sections: FormSectionType[]
  values: Record<string, any>
  onChange: (name: string, value: any) => void
  onSubmit: (values: Record<string, any>) => void
  errors: Record<string, string>
  isSubmitting?: boolean
  submitLabel?: string
  cancelLabel?: string
  onCancel?: () => void
}

export function DynamicForm({
  sections,
  values,
  onChange,
  onSubmit,
  errors,
  isSubmitting = false,
  submitLabel = 'Save',
  cancelLabel = 'Cancel',
  onCancel,
}: DynamicFormProps) {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(values)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-8">
      {sections.map((section, index) => (
        <div key={index}>
          <FormSection
            section={section}
            values={values}
            onChange={onChange}
            errors={errors}
          />
          
          {index < sections.length - 1 && (
            <hr className="mt-8 border-secondary-200" />
          )}
        </div>
      ))}
      
      <div className="flex items-center justify-end space-x-3 pt-6 border-t border-secondary-200">
        {onCancel && (
          <Button
            type="button"
            variant="outline"
            onClick={onCancel}
            disabled={isSubmitting}
          >
            {cancelLabel}
          </Button>
        )}
        
        <Button
          type="submit"
          loading={isSubmitting}
          disabled={isSubmitting}
        >
          {submitLabel}
        </Button>
      </div>
    </form>
  )
}