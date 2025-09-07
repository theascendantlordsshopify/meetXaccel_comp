import React, { useState } from 'react'
import { Upload, Download, FileText, CheckCircle, XCircle, AlertTriangle, ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { Checkbox } from '@/components/ui/Checkbox'
import { useContacts } from '@/hooks/useContacts'
import { ROUTES } from '@/constants/routes'

export default function ContactImport() {
  const [file, setFile] = useState<File | null>(null)
  const [skipDuplicates, setSkipDuplicates] = useState(true)
  const [updateExisting, setUpdateExisting] = useState(false)
  const [importStatus, setImportStatus] = useState<'idle' | 'uploading' | 'processing' | 'completed' | 'error'>('idle')
  const [importResults, setImportResults] = useState<any>(null)

  const { importContacts, isContactActionLoading } = useContacts()

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0]
    if (selectedFile && selectedFile.type === 'text/csv') {
      setFile(selectedFile)
    } else {
      alert('Please select a valid CSV file')
    }
  }

  const handleImport = async () => {
    if (!file) return

    setImportStatus('uploading')
    
    try {
      const result = await importContacts({
        csv_file: file,
        skip_duplicates: skipDuplicates,
        update_existing: updateExisting,
      })

      setImportStatus('completed')
      setImportResults(result)
    } catch (error) {
      setImportStatus('error')
      setImportResults({ error: 'Import failed' })
    }
  }

  const downloadTemplate = () => {
    const csvContent = 'first_name,last_name,email,phone,company,job_title,notes,tags\nJohn,Doe,john@example.com,+1234567890,Acme Corp,Software Engineer,Great client,"vip,tech"\nJane,Smith,jane@example.com,+1234567891,Beta Inc,Product Manager,Potential lead,"prospect,saas"'
    
    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'contacts_template.csv'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
  }

  const resetImport = () => {
    setFile(null)
    setImportStatus('idle')
    setImportResults(null)
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Import Contacts"
        subtitle="Import contacts from a CSV file to quickly build your contact list"
        breadcrumbs={[
          { label: 'Contacts', href: ROUTES.CONTACTS },
          { label: 'Import', current: true },
        ]}
        action={
          <Button
            variant="outline"
            onClick={() => window.location.href = ROUTES.CONTACTS}
            leftIcon={<ArrowLeft className="h-4 w-4" />}
          >
            Back to Contacts
          </Button>
        }
      />

      <Container>
        <div className="max-w-4xl mx-auto">
          {importStatus === 'idle' && (
            <div className="space-y-8">
              {/* Instructions */}
              <Card>
                <CardHeader title="Import Instructions" />
                <CardContent className="space-y-6">
                  <div className="bg-info-50 border border-info-200 rounded-lg p-4">
                    <h4 className="font-medium text-info-800 mb-2">Before You Start</h4>
                    <ul className="text-sm text-info-700 space-y-1 list-disc list-inside">
                      <li>Prepare your CSV file with the required columns</li>
                      <li>Ensure email addresses are valid and unique</li>
                      <li>Use comma-separated values for tags</li>
                      <li>Phone numbers should include country codes</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium text-secondary-900 mb-3">Required CSV Format</h4>
                    <div className="bg-secondary-50 p-4 rounded-lg">
                      <code className="text-sm text-secondary-700">
                        first_name,last_name,email,phone,company,job_title,notes,tags
                      </code>
                    </div>
                    <p className="text-sm text-secondary-600 mt-2">
                      Only the <strong>email</strong> column is required. All other columns are optional.
                    </p>
                  </div>

                  <div className="flex justify-center">
                    <Button
                      variant="outline"
                      onClick={downloadTemplate}
                      leftIcon={<Download className="h-4 w-4" />}
                    >
                      Download CSV Template
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* File Upload */}
              <Card>
                <CardHeader title="Upload CSV File" />
                <CardContent className="space-y-6">
                  <div className="border-2 border-dashed border-secondary-300 rounded-lg p-8 text-center hover:border-secondary-400 transition-colors">
                    <FileText className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
                    <div className="space-y-2">
                      <p className="text-lg font-medium text-secondary-900">
                        Choose CSV file to upload
                      </p>
                      <p className="text-sm text-secondary-600">
                        Select a CSV file from your computer
                      </p>
                    </div>
                    <div className="mt-4">
                      <input
                        type="file"
                        accept=".csv"
                        onChange={handleFileSelect}
                        className="hidden"
                        id="csv-upload"
                      />
                      <label htmlFor="csv-upload">
                        <Button
                          type="button"
                          variant="outline"
                          leftIcon={<Upload className="h-4 w-4" />}
                          className="cursor-pointer"
                        >
                          Select CSV File
                        </Button>
                      </label>
                    </div>
                  </div>

                  {file && (
                    <div className="bg-success-50 border border-success-200 rounded-lg p-4">
                      <div className="flex items-center space-x-3">
                        <CheckCircle className="h-5 w-5 text-success-500" />
                        <div>
                          <p className="text-sm font-medium text-success-800">
                            File selected: {file.name}
                          </p>
                          <p className="text-xs text-success-600">
                            Size: {(file.size / 1024).toFixed(1)} KB
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Import Options */}
                  <div className="space-y-4">
                    <h4 className="font-medium text-secondary-900">Import Options</h4>
                    
                    <Checkbox
                      checked={skipDuplicates}
                      onChange={setSkipDuplicates}
                      label="Skip duplicate contacts"
                      description="Skip contacts with email addresses that already exist"
                    />

                    <Checkbox
                      checked={updateExisting}
                      onChange={setUpdateExisting}
                      label="Update existing contacts"
                      description="Update existing contacts with new information from CSV"
                    />
                  </div>

                  <div className="flex space-x-3">
                    <Button
                      variant="outline"
                      onClick={() => window.location.href = ROUTES.CONTACTS}
                      className="flex-1"
                    >
                      Cancel
                    </Button>
                    <Button
                      onClick={handleImport}
                      disabled={!file || isContactActionLoading}
                      loading={isContactActionLoading}
                      className="flex-1"
                      leftIcon={<Upload className="h-4 w-4" />}
                    >
                      Import Contacts
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {importStatus === 'processing' && (
            <Card>
              <CardContent className="p-12 text-center">
                <LoadingSpinner size="lg" />
                <h3 className="text-lg font-semibold text-secondary-900 mt-4">
                  Processing Import
                </h3>
                <p className="text-secondary-600 mt-2">
                  Please wait while we import your contacts...
                </p>
              </CardContent>
            </Card>
          )}

          {importStatus === 'completed' && (
            <Card>
              <CardHeader title="Import Completed" />
              <CardContent className="space-y-6">
                <div className="text-center">
                  <div className="w-16 h-16 bg-success-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <CheckCircle className="h-8 w-8 text-success-600" />
                  </div>
                  <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                    Import Successful!
                  </h3>
                  <p className="text-secondary-600">
                    Your contacts have been imported successfully.
                  </p>
                </div>

                {importResults && (
                  <div className="bg-secondary-50 p-4 rounded-lg">
                    <h4 className="font-medium text-secondary-900 mb-2">Import Summary</h4>
                    <div className="grid grid-cols-3 gap-4 text-center">
                      <div>
                        <p className="text-2xl font-bold text-success-600">
                          {importResults.created || 0}
                        </p>
                        <p className="text-sm text-secondary-600">Created</p>
                      </div>
                      <div>
                        <p className="text-2xl font-bold text-warning-600">
                          {importResults.updated || 0}
                        </p>
                        <p className="text-sm text-secondary-600">Updated</p>
                      </div>
                      <div>
                        <p className="text-2xl font-bold text-secondary-600">
                          {importResults.skipped || 0}
                        </p>
                        <p className="text-sm text-secondary-600">Skipped</p>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex space-x-3">
                  <Button
                    variant="outline"
                    onClick={resetImport}
                    className="flex-1"
                  >
                    Import More
                  </Button>
                  <Button
                    onClick={() => window.location.href = ROUTES.CONTACTS}
                    className="flex-1"
                  >
                    View Contacts
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {importStatus === 'error' && (
            <Card>
              <CardHeader title="Import Failed" />
              <CardContent className="space-y-6">
                <div className="text-center">
                  <div className="w-16 h-16 bg-error-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <XCircle className="h-8 w-8 text-error-600" />
                  </div>
                  <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                    Import Failed
                  </h3>
                  <p className="text-secondary-600">
                    There was an error importing your contacts.
                  </p>
                </div>

                {importResults?.error && (
                  <div className="bg-error-50 border border-error-200 rounded-lg p-4">
                    <div className="flex items-center space-x-2">
                      <AlertTriangle className="h-4 w-4 text-error-500" />
                      <p className="text-sm font-medium text-error-800">Error Details</p>
                    </div>
                    <p className="text-sm text-error-700 mt-1">
                      {importResults.error}
                    </p>
                  </div>
                )}

                <div className="flex space-x-3">
                  <Button
                    variant="outline"
                    onClick={resetImport}
                    className="flex-1"
                  >
                    Try Again
                  </Button>
                  <Button
                    onClick={() => window.location.href = ROUTES.CONTACTS}
                    className="flex-1"
                  >
                    Back to Contacts
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </Container>
    </div>
  )
}