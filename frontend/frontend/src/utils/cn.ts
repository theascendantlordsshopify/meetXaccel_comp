import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * Utility function to merge Tailwind CSS classes
 * Combines clsx for conditional classes and tailwind-merge for deduplication
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Create a class name builder for consistent component styling
 */
export function createClassBuilder(baseClasses: string) {
  return (...additionalClasses: ClassValue[]) => {
    return cn(baseClasses, ...additionalClasses)
  }
}

/**
 * Conditional class utility
 */
export function conditionalClass(condition: boolean, trueClass: string, falseClass?: string) {
  return condition ? trueClass : falseClass || ''
}

/**
 * Variant class utility for component variants
 */
export function variantClass<T extends string>(
  variant: T,
  variants: Record<T, string>,
  defaultVariant?: T
) {
  return variants[variant] || (defaultVariant ? variants[defaultVariant] : '')
}

/**
 * Size class utility for component sizes
 */
export function sizeClass<T extends string>(
  size: T,
  sizes: Record<T, string>,
  defaultSize?: T
) {
  return sizes[size] || (defaultSize ? sizes[defaultSize] : '')
}