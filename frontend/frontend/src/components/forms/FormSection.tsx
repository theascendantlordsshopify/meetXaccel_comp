import React from 'react'
import { FormField } from './FormField'
import type { FormSection as FormSectionType } from '@/types/common'

interface FormSectionProps {
  section: FormSectionType
  values: Record<string, any>
  onChange: (name: string, value: any) => void
  errors: Record<string, string>
}

export function FormSection({ 
  section, 
  values, 
  onChange, 
  errors 
}: FormSectionProps) {
  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium text-secondary-900">
          {section.title}
        </h3>
        {section.description && (
          <p className="mt-1 text-sm text-secondary-500">
            {section.description}
          </p>
        )}
      </div>
      
      <div className="space-y-4">
        {section.fields.map((field) => (
          <FormField
            key={field.name}
            field={field}
            value={values[field.name]}
            onChange={(value) => onChange(field.name, value)}
            error={errors[field.name]}
          />
        ))}
      </div>
    </div>
  )
}