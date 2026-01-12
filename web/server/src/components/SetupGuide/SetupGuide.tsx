import { useState } from 'react'

type Platform = 'macos' | 'windows' | 'linux' | 'browser'

interface CodeBlockProps {
  code: string
  language?: string
}

function CodeBlock({ code }: CodeBlockProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="relative group">
      <pre className="code-block text-gray-300 text-sm overflow-x-auto">
        {code}
      </pre>
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 btn btn-ghost text-xs opacity-0 group-hover:opacity-100 transition-opacity"
      >
        {copied ? 'Copied!' : 'Copy'}
      </button>
    </div>
  )
}

interface SectionProps {
  title: string
  children: React.ReactNode
}

function Section({ title, children }: SectionProps) {
  return (
    <div className="space-y-3">
      <h4 className="text-lg font-medium text-white">{title}</h4>
      {children}
    </div>
  )
}

export function SetupGuideContent() {
  const [platform, setPlatform] = useState<Platform>('macos')

  const proxyHost = window.location.hostname
  const httpPort = '8080'
  const socks5Port = '1080'
  const pacUrl = `${window.location.origin}/proxy.pac`

  const platforms: { id: Platform; label: string; icon: string }[] = [
    { id: 'macos', label: 'macOS', icon: '' },
    { id: 'windows', label: 'Windows', icon: '' },
    { id: 'linux', label: 'Linux', icon: '' },
    { id: 'browser', label: 'Browser', icon: '' },
  ]

  return (
    <div className="space-y-8">
      {/* PAC File Section */}
      <div className="card bg-gradient-to-r from-bifrost-accent/10 to-transparent border-bifrost-accent/30">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white mb-2">PAC File (Recommended)</h3>
            <p className="text-gray-400 text-sm mb-4">
              Use the Proxy Auto-Configuration file for automatic routing based on your server's rules.
            </p>
            <CodeBlock code={pacUrl} />
          </div>
          <div className="flex gap-2">
            <a
              href="/proxy.pac"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary text-sm"
            >
              View
            </a>
            <a
              href="/proxy.pac"
              download="proxy.pac"
              className="btn btn-primary text-sm"
            >
              Download
            </a>
          </div>
        </div>
      </div>

      {/* Platform Selector */}
      <div>
        <h3 className="text-lg font-semibold text-white mb-4">Setup Instructions</h3>
        <div className="flex flex-wrap gap-2 mb-6">
          {platforms.map((p) => (
            <button
              key={p.id}
              onClick={() => setPlatform(p.id)}
              className={`tab ${platform === p.id ? 'tab-active' : 'tab-inactive'}`}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Platform-specific content */}
        <div className="space-y-6">
          {platform === 'macos' && (
            <>
              <Section title="System Proxy (GUI)">
                <ol className="list-decimal list-inside space-y-2 text-gray-400">
                  <li>Open <strong className="text-white">System Preferences</strong> → <strong className="text-white">Network</strong></li>
                  <li>Select your network connection and click <strong className="text-white">Advanced</strong></li>
                  <li>Go to the <strong className="text-white">Proxies</strong> tab</li>
                  <li>For HTTP proxy: Enter <code className="bg-bifrost-bg px-1 rounded">{proxyHost}:{httpPort}</code></li>
                  <li>For SOCKS proxy: Enter <code className="bg-bifrost-bg px-1 rounded">{proxyHost}:{socks5Port}</code></li>
                  <li>Or use Automatic Proxy Configuration URL: <code className="bg-bifrost-bg px-1 rounded">{pacUrl}</code></li>
                </ol>
              </Section>

              <Section title="Terminal">
                <CodeBlock code={`# HTTP Proxy
export http_proxy=http://${proxyHost}:${httpPort}
export https_proxy=http://${proxyHost}:${httpPort}

# SOCKS5 Proxy
export all_proxy=socks5://${proxyHost}:${socks5Port}

# Add to ~/.zshrc or ~/.bashrc for persistence`} />
              </Section>

              <Section title="networksetup (Command Line)">
                <CodeBlock code={`# Set HTTP proxy
networksetup -setwebproxy "Wi-Fi" ${proxyHost} ${httpPort}
networksetup -setsecurewebproxy "Wi-Fi" ${proxyHost} ${httpPort}

# Set SOCKS proxy
networksetup -setsocksfirewallproxy "Wi-Fi" ${proxyHost} ${socks5Port}

# Set PAC file
networksetup -setautoproxyurl "Wi-Fi" "${pacUrl}"

# Disable proxies
networksetup -setwebproxystate "Wi-Fi" off
networksetup -setsecurewebproxystate "Wi-Fi" off
networksetup -setsocksfirewallproxystate "Wi-Fi" off`} />
              </Section>
            </>
          )}

          {platform === 'windows' && (
            <>
              <Section title="System Proxy (GUI)">
                <ol className="list-decimal list-inside space-y-2 text-gray-400">
                  <li>Open <strong className="text-white">Settings</strong> → <strong className="text-white">Network & Internet</strong> → <strong className="text-white">Proxy</strong></li>
                  <li>Under Manual proxy setup, enable <strong className="text-white">Use a proxy server</strong></li>
                  <li>Enter Address: <code className="bg-bifrost-bg px-1 rounded">{proxyHost}</code> Port: <code className="bg-bifrost-bg px-1 rounded">{httpPort}</code></li>
                  <li>Or use Automatic setup with script address: <code className="bg-bifrost-bg px-1 rounded">{pacUrl}</code></li>
                </ol>
              </Section>

              <Section title="PowerShell">
                <CodeBlock code={`# Set environment variables
$env:HTTP_PROXY = "http://${proxyHost}:${httpPort}"
$env:HTTPS_PROXY = "http://${proxyHost}:${httpPort}"

# Set permanently (user)
[Environment]::SetEnvironmentVariable("HTTP_PROXY", "http://${proxyHost}:${httpPort}", "User")
[Environment]::SetEnvironmentVariable("HTTPS_PROXY", "http://${proxyHost}:${httpPort}", "User")`} />
              </Section>

              <Section title="Command Prompt">
                <CodeBlock code={`set HTTP_PROXY=http://${proxyHost}:${httpPort}
set HTTPS_PROXY=http://${proxyHost}:${httpPort}

:: Permanently
setx HTTP_PROXY http://${proxyHost}:${httpPort}
setx HTTPS_PROXY http://${proxyHost}:${httpPort}`} />
              </Section>
            </>
          )}

          {platform === 'linux' && (
            <>
              <Section title="Environment Variables">
                <CodeBlock code={`# Add to ~/.bashrc or ~/.profile
export http_proxy=http://${proxyHost}:${httpPort}
export https_proxy=http://${proxyHost}:${httpPort}
export HTTP_PROXY=http://${proxyHost}:${httpPort}
export HTTPS_PROXY=http://${proxyHost}:${httpPort}

# SOCKS5
export all_proxy=socks5://${proxyHost}:${socks5Port}
export ALL_PROXY=socks5://${proxyHost}:${socks5Port}

# No proxy for local addresses
export no_proxy=localhost,127.0.0.1,::1`} />
              </Section>

              <Section title="GNOME (System-wide)">
                <CodeBlock code={`# Using gsettings
gsettings set org.gnome.system.proxy mode 'manual'
gsettings set org.gnome.system.proxy.http host '${proxyHost}'
gsettings set org.gnome.system.proxy.http port ${httpPort}
gsettings set org.gnome.system.proxy.https host '${proxyHost}'
gsettings set org.gnome.system.proxy.https port ${httpPort}

# Or use PAC file
gsettings set org.gnome.system.proxy mode 'auto'
gsettings set org.gnome.system.proxy autoconfig-url '${pacUrl}'`} />
              </Section>

              <Section title="apt (Debian/Ubuntu)">
                <CodeBlock code={`# /etc/apt/apt.conf.d/proxy.conf
Acquire::http::Proxy "http://${proxyHost}:${httpPort}";
Acquire::https::Proxy "http://${proxyHost}:${httpPort}";`} />
              </Section>
            </>
          )}

          {platform === 'browser' && (
            <>
              <Section title="Chrome / Edge">
                <p className="text-gray-400 mb-3">Chrome uses system proxy settings by default. To use a different proxy:</p>
                <CodeBlock code={`# Launch with custom proxy
google-chrome --proxy-server="http://${proxyHost}:${httpPort}"

# Or with PAC file
google-chrome --proxy-pac-url="${pacUrl}"

# SOCKS5
google-chrome --proxy-server="socks5://${proxyHost}:${socks5Port}"`} />
              </Section>

              <Section title="Firefox">
                <ol className="list-decimal list-inside space-y-2 text-gray-400">
                  <li>Open <strong className="text-white">Settings</strong> → <strong className="text-white">General</strong> → <strong className="text-white">Network Settings</strong></li>
                  <li>Click <strong className="text-white">Settings...</strong></li>
                  <li>Select <strong className="text-white">Manual proxy configuration</strong></li>
                  <li>HTTP Proxy: <code className="bg-bifrost-bg px-1 rounded">{proxyHost}</code> Port: <code className="bg-bifrost-bg px-1 rounded">{httpPort}</code></li>
                  <li>SOCKS Host: <code className="bg-bifrost-bg px-1 rounded">{proxyHost}</code> Port: <code className="bg-bifrost-bg px-1 rounded">{socks5Port}</code></li>
                  <li>Or use Automatic proxy configuration URL: <code className="bg-bifrost-bg px-1 rounded">{pacUrl}</code></li>
                </ol>
              </Section>

              <Section title="Safari">
                <p className="text-gray-400">
                  Safari uses macOS system proxy settings. Configure proxy in{' '}
                  <strong className="text-white">System Preferences → Network → Proxies</strong>.
                </p>
              </Section>
            </>
          )}
        </div>
      </div>

      {/* Common Tools */}
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Common Tools</h3>
        <div className="space-y-4">
          <Section title="curl">
            <CodeBlock code={`# HTTP proxy
curl -x http://${proxyHost}:${httpPort} https://example.com

# SOCKS5 proxy
curl --socks5 ${proxyHost}:${socks5Port} https://example.com

# With authentication
curl -x http://user:pass@${proxyHost}:${httpPort} https://example.com`} />
          </Section>

          <Section title="wget">
            <CodeBlock code={`# HTTP proxy
wget -e http_proxy=http://${proxyHost}:${httpPort} https://example.com

# Or use environment variables
export http_proxy=http://${proxyHost}:${httpPort}
wget https://example.com`} />
          </Section>

          <Section title="git">
            <CodeBlock code={`# Configure git to use HTTP proxy
git config --global http.proxy http://${proxyHost}:${httpPort}

# SOCKS5 proxy
git config --global http.proxy socks5://${proxyHost}:${socks5Port}

# Remove proxy config
git config --global --unset http.proxy`} />
          </Section>

          <Section title="npm">
            <CodeBlock code={`npm config set proxy http://${proxyHost}:${httpPort}
npm config set https-proxy http://${proxyHost}:${httpPort}

# Remove
npm config delete proxy
npm config delete https-proxy`} />
          </Section>
        </div>
      </div>
    </div>
  )
}
