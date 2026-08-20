import { createContext, useContext } from 'react'
import type { ConfigSectionKey } from './sectionMeta'

/**
 * State the config editor shares with every rendered `<Section>`:
 *
 *  - `hotReloadable` comes from the server's `/config/meta` endpoint, so the
 *    "Hot Reload" / "Restart Required" badge always reflects what the running
 *    server will actually do rather than a hand-maintained client-side copy.
 *  - `dirtySections` drives the per-section "Modified" marker so an operator can
 *    see what they changed without diffing 17 collapsed panels.
 *  - `openSections` / `toggleSection` make expansion controlled, which lets the
 *    sidebar open a collapsed section when it is navigated to.
 */
export interface ConfigSectionState {
  hotReloadable: (key: ConfigSectionKey) => boolean
  dirtySections: ReadonlySet<ConfigSectionKey>
  openSections: ReadonlySet<ConfigSectionKey>
  toggleSection: (key: ConfigSectionKey) => void
}

const ConfigSectionContext = createContext<ConfigSectionState | null>(null)

export const ConfigSectionProvider = ConfigSectionContext.Provider

export function useConfigSectionState(): ConfigSectionState | null {
  return useContext(ConfigSectionContext)
}
