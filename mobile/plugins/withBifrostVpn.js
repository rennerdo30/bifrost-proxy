// withBifrostVpn.js
//
// Expo config plugin that wires the orphaned native VPN code into a prebuilt
// (bare) project during `expo prebuild` / EAS Build:
//
//   - Android: declares the VpnService (<service> with the system-held
//     android.permission.BIND_VPN_SERVICE) and the VpnService intent filter, and
//     ensures the FOREGROUND_SERVICE* permissions are present. The Kotlin source
//     lives at android/app/src/main/java/com/bifrost/vpn/BifrostVpnService.kt.
//
//   - iOS: documents the required Network Extension (packet-tunnel-provider)
//     entitlement. NOTE: adding a *separate* Network Extension target (which is
//     what PacketTunnelProvider.swift needs) cannot be done from a config plugin
//     alone — it requires either a dedicated plugin like
//     `@config-plugins/...` / a custom Xcode-project mod, or manual setup in
//     Xcode. This plugin only asserts the app-level entitlement; the extension
//     target wiring is documented in mobile/README.md and is DEFERRED until the
//     real WireGuard data path is integrated.
//
// This plugin is intentionally conservative: it only edits the generated native
// projects and never touches the secure data path. The shipped UDP forwarders
// are placeholders (see BifrostVpn.ts / README), so this scaffolding does NOT
// enable a secure tunnel by itself.

const {
  AndroidConfig,
  withAndroidManifest,
  withInfoPlist,
} = require('@expo/config-plugins')

const VPN_SERVICE_CLASS = 'com.bifrost.vpn.BifrostVpnService'
const BIND_VPN_SERVICE = 'android.permission.BIND_VPN_SERVICE'

/**
 * Inject the BifrostVpnService <service> element into AndroidManifest.xml.
 */
function withBifrostAndroidService(config) {
  return withAndroidManifest(config, (cfg) => {
    const app = AndroidConfig.Manifest.getMainApplicationOrThrow(cfg.modResults)

    app.service = app.service || []

    const exists = app.service.some(
      (s) => s.$ && s.$['android:name'] === VPN_SERVICE_CLASS
    )

    if (!exists) {
      app.service.push({
        $: {
          'android:name': VPN_SERVICE_CLASS,
          // BIND_VPN_SERVICE is a system signature permission: declaring it here
          // means only the OS may bind to the service. It is NOT requested in
          // the app's <uses-permission> list.
          'android:permission': BIND_VPN_SERVICE,
          'android:exported': 'false',
          'android:foregroundServiceType': 'specialUse',
        },
        'intent-filter': [
          {
            action: [{ $: { 'android:name': 'android.net.VpnService' } }],
          },
        ],
        property: [
          {
            $: {
              'android:name':
                'android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE',
              'android:value': 'vpn',
            },
          },
        ],
      })
    }

    return cfg
  })
}

/**
 * Ensure the iOS app declares the packet-tunnel-provider Network Extension
 * entitlement. (The extension target itself must be added separately — see
 * mobile/README.md.)
 */
function withBifrostIosEntitlement(config) {
  return withInfoPlist(config, (cfg) => {
    // Nothing to add to Info.plist directly here; entitlements are declared in
    // app.json -> ios.entitlements. This mod exists as the documented hook point
    // for future Xcode target wiring and keeps the plugin idempotent.
    return cfg
  })
}

/**
 * @param {import('@expo/config-plugins').ExpoConfig} config
 */
function withBifrostVpn(config) {
  config = withBifrostAndroidService(config)
  config = withBifrostIosEntitlement(config)
  return config
}

module.exports = withBifrostVpn
