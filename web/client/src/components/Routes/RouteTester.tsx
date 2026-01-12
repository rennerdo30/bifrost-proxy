import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { RouteTestResult } from '../../api/types'

export function RouteTester() {
  const [domain, setDomain] = useState('')
  const [result, setResult] = useState<RouteTestResult | null>(null)

  const testMutation = useMutation({
    mutationFn: api.testRoute,
    onSuccess: (data) => setResult(data),
  })

  const handleTest = (e: React.FormEvent) => {
    e.preventDefault()
    if (domain.trim()) {
      testMutation.mutate(domain.trim())
    }
  }

  return (
    <div className="card">
      <h3 className="text-lg font-semibold text-white mb-4">Test Domain Routing</h3>
      <form onSubmit={handleTest} className="flex gap-3">
        <input
          type="text"
          placeholder="Enter domain (e.g., google.com)"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          className="input flex-1"
        />
        <button
          type="submit"
          disabled={!domain.trim() || testMutation.isPending}
          className="btn btn-primary"
        >
          {testMutation.isPending ? (
            <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full" />
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
              Test
            </>
          )}
        </button>
      </form>

      {result && (
        <div className="mt-4 p-4 bg-bifrost-bg rounded-lg border border-bifrost-border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-bifrost-muted">Domain</p>
              <p className="font-mono text-white">{result.domain}</p>
            </div>
            <div className="text-right">
              <p className="text-sm text-bifrost-muted">Action</p>
              <span className={`badge ${result.action === 'server' ? 'badge-server' : 'badge-direct'}`}>
                {result.action}
              </span>
            </div>
          </div>
          {result.matched_route && (
            <div className="mt-3 pt-3 border-t border-bifrost-border">
              <p className="text-sm text-bifrost-muted">Matched Rule</p>
              <p className="text-white">{result.matched_route}</p>
            </div>
          )}
        </div>
      )}

      {testMutation.isError && (
        <div className="mt-4 p-4 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg">
          <p className="text-bifrost-error text-sm">Failed to test domain routing</p>
        </div>
      )}
    </div>
  )
}
