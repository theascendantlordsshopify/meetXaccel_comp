import React from 'react'
import { ChevronUp, ChevronDown } from 'lucide-react'
import { cn } from '@/utils/cn'
import { LoadingSpinner } from './LoadingSpinner'
import { EmptyState } from './EmptyState'
import type { TableProps, SortDirection } from '@/types'

export function Table<T = any>({
  columns,
  data,
  loading = false,
  error,
  emptyMessage = 'No data available',
  sortable = false,
  selectable = false,
  onSort,
  onSelect,
  className,
  'data-testid': testId,
}: TableProps<T>) {
  const [selectedRows, setSelectedRows] = React.useState<T[]>([])
  const [sortConfig, setSortConfig] = React.useState<{
    key: string
    direction: SortDirection
  } | null>(null)

  const handleSort = (columnKey: string) => {
    if (!sortable || !onSort) return

    let direction: SortDirection = 'asc'
    
    if (sortConfig && sortConfig.key === columnKey && sortConfig.direction === 'asc') {
      direction = 'desc'
    }

    setSortConfig({ key: columnKey, direction })
    onSort(columnKey, direction)
  }

  const handleSelectAll = (checked: boolean) => {
    const newSelection = checked ? [...data] : []
    setSelectedRows(newSelection)
    onSelect?.(newSelection)
  }

  const handleSelectRow = (row: T, checked: boolean) => {
    const newSelection = checked
      ? [...selectedRows, row]
      : selectedRows.filter(r => r !== row)
    
    setSelectedRows(newSelection)
    onSelect?.(newSelection)
  }

  const isRowSelected = (row: T) => selectedRows.includes(row)
  const isAllSelected = data.length > 0 && selectedRows.length === data.length
  const isIndeterminate = selectedRows.length > 0 && selectedRows.length < data.length

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-error-600">{error}</p>
      </div>
    )
  }

  if (data.length === 0) {
    return <EmptyState title={emptyMessage} />
  }

  return (
    <div className={cn('overflow-hidden', className)} data-testid={testId}>
      <div className="overflow-x-auto">
        <table className="table">
          <thead className="table-header">
            <tr>
              {selectable && (
                <th className="table-head w-12">
                  <input
                    type="checkbox"
                    checked={isAllSelected}
                    ref={(input) => {
                      if (input) input.indeterminate = isIndeterminate
                    }}
                    onChange={(e) => handleSelectAll(e.target.checked)}
                    className="rounded border-secondary-300 text-primary-600 focus:ring-primary-500"
                  />
                </th>
              )}
              
              {columns.map((column) => (
                <th
                  key={column.key}
                  className={cn(
                    'table-head',
                    column.align === 'center' && 'text-center',
                    column.align === 'right' && 'text-right',
                    sortable && column.sortable && 'cursor-pointer hover:bg-secondary-50'
                  )}
                  style={{ width: column.width }}
                  onClick={() => column.sortable && handleSort(column.key)}
                >
                  <div className="flex items-center space-x-1">
                    <span>{column.label}</span>
                    {sortable && column.sortable && (
                      <div className="flex flex-col">
                        <ChevronUp
                          className={cn(
                            'h-3 w-3',
                            sortConfig?.key === column.key && sortConfig.direction === 'asc'
                              ? 'text-primary-600'
                              : 'text-secondary-400'
                          )}
                        />
                        <ChevronDown
                          className={cn(
                            'h-3 w-3 -mt-1',
                            sortConfig?.key === column.key && sortConfig.direction === 'desc'
                              ? 'text-primary-600'
                              : 'text-secondary-400'
                          )}
                        />
                      </div>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          
          <tbody>
            {data.map((row, index) => (
              <tr key={index} className="table-row">
                {selectable && (
                  <td className="table-cell">
                    <input
                      type="checkbox"
                      checked={isRowSelected(row)}
                      onChange={(e) => handleSelectRow(row, e.target.checked)}
                      className="rounded border-secondary-300 text-primary-600 focus:ring-primary-500"
                    />
                  </td>
                )}
                
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={cn(
                      'table-cell',
                      column.align === 'center' && 'text-center',
                      column.align === 'right' && 'text-right',
                      column.className
                    )}
                  >
                    {column.render
                      ? column.render(row[column.key as keyof T], row, index)
                      : String(row[column.key as keyof T] || '')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}