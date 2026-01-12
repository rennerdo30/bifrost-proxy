import { useState } from 'react'
import yaml from 'js-yaml'
import { GeneratorForm } from '../components/ConfigGenerator/GeneratorForm'
import { YamlPreview } from '../components/ConfigGenerator/YamlPreview'

const initialYaml = yaml.dump({
  server: {
    address: 'localhost:8080',
    protocol: 'http',
  },
  local: {
    http_listen: ':8080',
    socks5_listen: ':1080',
  },
  routes: [
    { pattern: '*.local', action: 'direct' },
    { pattern: 'localhost', action: 'direct' },
    { pattern: '*', action: 'proxy' },
  ],
}, { indent: 2, lineWidth: -1 })

export function ConfigGenerator() {
  const [generatedYaml, setGeneratedYaml] = useState(initialYaml)

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h2 className="text-2xl font-bold text-white">Config Generator</h2>
        <p className="text-bifrost-muted mt-1">
          Generate client configuration files for the Bifrost client
        </p>
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Form */}
        <div>
          <GeneratorForm onConfigChange={setGeneratedYaml} />
        </div>

        {/* Preview */}
        <div className="lg:sticky lg:top-6 lg:self-start">
          <YamlPreview yaml={generatedYaml} />
        </div>
      </div>
    </div>
  )
}
