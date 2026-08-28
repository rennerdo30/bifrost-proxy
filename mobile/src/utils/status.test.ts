import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { getConnectionStatusColor, getStatusColor } from './status.ts'

describe('getStatusColor', () => {
  it('maps online, offline, busy and unknown server states', () => {
    assert.equal(getStatusColor('online'), '#22c55e')
    assert.equal(getStatusColor('offline'), '#ef4444')
    assert.equal(getStatusColor('busy'), '#f59e0b')
    assert.equal(getStatusColor('unknown'), '#6b7280')
    assert.equal(getStatusColor('future-state'), '#6b7280')
  })
})

describe('getConnectionStatusColor', () => {
  it('keeps unreachable distinct from disconnected', () => {
    assert.equal(getConnectionStatusColor('connected'), '#22c55e')
    assert.equal(getConnectionStatusColor('connecting'), '#f59e0b')
    assert.equal(getConnectionStatusColor('disconnected'), '#6b7280')
    assert.equal(getConnectionStatusColor('error'), '#ef4444')
    assert.equal(getConnectionStatusColor('unreachable'), '#ef4444')
  })
})
