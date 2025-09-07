import React from 'react'
import { Table } from '@/components/ui/Table'
import { Pagination } from '@/components/ui/Pagination'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Button } from '@/components/ui/Button'
import { Search, Filter, Download } from 'lucide-react'
import { cn } from '@/utils/cn'
import { useDebounce } from '@/hooks/useDebounce'
import type { TableColumn, SortDirection, FilterConfig, PaginationConfig } from '@/types/common'

interface DataTableProps<T = any> {
  columns: TableColumn<T>[]
  data: T[]
  loading?: boolean
  error?: string
  emptyMessage?: string
  
  // Search
  searchable?: boolean
  searchPlaceholder?: string
  onSearch?: (query: string) => void
  
  // Filtering
  filterable?: boolean
  filters?: FilterConfig
  onFilterChange?: (filters: FilterConfig) => void
  
  // Sorting
  sortable?: boolean
  onSort?: (column: string, direction: SortDirection) => void
  
  // Selection
  selectable?: boolean
  onSelect?: (selectedRows: T[]) => void
  
  // Pagination
  pagination?: PaginationConfig
  onPageChange?: (page: number) => void
  onPageSizeChange?: (pageSize: number) => void
  
  // Actions
  actions?: React.ReactNode
  bulkActions?: React.ReactNode
  onExport?: () => void
  
  className?: string
}

export function DataTable<T = any>({
  columns,
  data,
  loading = false,
  error,
  emptyMessage,
  searchable = false,
  searchPlaceholder = 'Search...',
  onSearch,
  filterable = false,
  filters,
  onFilterChange,
  sortable = false,
  onSort,
  selectable = false,
  onSelect,
  pagination,
  onPageChange,
  onPageSizeChange,
  actions,
  bulkActions,
  onExport,
  className,
}: DataTableProps<T>) {
  const [searchQuery, setSearchQuery] = React.useState('')
  const [selectedRows, setSelectedRows] = React.useState<T[]>([])
  
  const debouncedSearch = useDebounce(searchQuery, 300)

  React.useEffect(() => {
    if (onSearch) {
      onSearch(debouncedSearch)
    }
  }, [debouncedSearch, onSearch])

  const handleSelect = (rows: T[]) => {
    setSelectedRows(rows)
    onSelect?.(rows)
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* Header with search, filters, and actions */}
      {(searchable || filterable || actions || onExport) && (
        <div className="flex items-center justify-between space-x-4">
          <div className="flex items-center space-x-4 flex-1">
            {searchable && (
              <div className="max-w-sm">
                <Input
                  type="text"
                  placeholder={searchPlaceholder}
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  leftIcon={<Search className="h-4 w-4" />}
                />
              </div>
            )}
            
            {filterable && (
              <Button variant="outline" size="sm">
                <Filter className="h-4 w-4 mr-2" />
                Filters
              </Button>
            )}
          </div>
          
          <div className="flex items-center space-x-2">
            {selectedRows.length > 0 && bulkActions && (
              <div className="flex items-center space-x-2">
                <span className="text-sm text-secondary-600">
                  {selectedRows.length} selected
                </span>
                {bulkActions}
              </div>
            )}
            
            {onExport && (
              <Button variant="outline" size="sm" onClick={onExport}>
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
            )}
            
            {actions}
          </div>
        </div>
      )}

      {/* Table */}
      <Table
        columns={columns}
        data={data}
        loading={loading}
        error={error}
        emptyMessage={emptyMessage}
        sortable={sortable}
        selectable={selectable}
        onSort={onSort}
        onSelect={handleSelect}
      />

      {/* Pagination */}
      {pagination && (
        <Pagination
          currentPage={pagination.page}
          totalPages={Math.ceil(pagination.total / pagination.pageSize)}
          pageSize={pagination.pageSize}
          totalItems={pagination.total}
          onPageChange={onPageChange || (() => {})}
          onPageSizeChange={onPageSizeChange}
        />
      )}
    </div>
  )
}