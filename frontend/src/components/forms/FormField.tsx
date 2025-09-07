import React from 'react'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
import type { FormField as FormFieldType } from '@/types/common'

interface FormFieldProps {
  field: FormFieldType
  value: any
  onChange: (value: any) => void
  error?: string
}

export function FormField({ field, value, onChange, error }: FormFieldProps) {
  const commonProps = {
    name: field.name,
    label: field.label,
    required: field.required,
    placeholder: field.placeholder,
    helpText: field.helpText,
    error,
    value,
    onChange,
  }

  switch (field.type) {
    case 'text':
    case 'email':
    case 'password':
    case 'number':
    case 'tel':
    case 'url':
      return <Input type={field.type} {...commonProps} />
    
    case 'textarea':
      return <Textarea {...commonProps} />
    
    case 'select':
      return (
        <Select
          options={field.options || []}
          {...commonProps}
        />
      )
    
    case 'multiselect':
      return (
        <Select
          options={field.options || []}
          multiple
          {...commonProps}
        />
      )
    
    case 'checkbox':
      return (
        <Checkbox
          checked={value}
          onChange={onChange}
          label={field.label}
          error={error}
        />
      )
    
    default:
      return <Input {...commonProps} />
  }
}