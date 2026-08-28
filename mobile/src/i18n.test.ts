import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { formatNumber, setLocaleForTesting, t } from './i18n.ts'

after(() => setLocaleForTesting('en'))

describe('mobile i18n', () => {
  it('ships English and German translations with interpolation', () => {
    setLocaleForTesting('en')
    assert.equal(t('home.connectionStatus', { status: 'Protected' }), 'Connection status: Protected')

    setLocaleForTesting('de')
    assert.equal(t('home.connectionStatus', { status: 'Geschützt' }), 'Verbindungsstatus: Geschützt')
    assert.equal(t('split.removeDomainMessage', { domain: 'example.com' }), '„example.com“ aus dem geteilten Tunneling entfernen?')
  })

  it('formats counters with the selected locale', () => {
    setLocaleForTesting('en')
    assert.equal(formatNumber(1234), '1,234')

    setLocaleForTesting('de')
    assert.equal(formatNumber(1234), '1.234')
  })
})
