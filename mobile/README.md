# Bifrost Mobile (Expo)

React Native / Expo app for the Bifrost proxy. Today the app is a **management
client**: it talks to a running Bifrost *client* over its REST API
(`/api/v1/...`) to view status and toggle the server-side VPN. See
`src/services/api.ts`.

This directory also contains the scaffolding for an **on-device native VPN**
(iOS Network Extension + Android `VpnService`). That native path is **not built
or shipped yet** — see "Native VPN status" below before relying on it.

## Quick start

```bash
cd mobile
npm install
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm start           # expo start (Expo Go: management UI only, no native VPN)
```

`node_modules/` is gitignored and must be installed locally; there is no test
runner wired up yet (no `jest`/`jest-expo`), so `npm run typecheck` +
`npm run lint` are the CI gates for this package.

## Project layout

```
mobile/
├── App.tsx                 # App root (navigation, query client, theme)
├── app.json                # Expo config (plugins, permissions, entitlements)
├── eas.json                # EAS Build profiles (dev/preview/production)
├── plugins/
│   └── withBifrostVpn.js   # Config plugin: wires native VPN into prebuild
├── src/
│   ├── native/
│   │   ├── BifrostVpn.ts   # JS bridge to native modules (safe no-op stub)
│   │   └── index.ts        # barrel + selectVpnMode/buildNativeVpnConfig
│   ├── services/api.ts     # REST client for the Bifrost client API
│   └── screens/ ...        # UI
├── ios/BifrostVPN/
│   └── PacketTunnelProvider.swift   # iOS NEPacketTunnelProvider (NOT linked)
└── android/app/src/main/java/com/bifrost/vpn/
    └── BifrostVpnService.kt         # Android VpnService (NOT linked)
```

## Native VPN status (READ THIS)

> [!WARNING]
> The native VPN data path is a **placeholder, not a secure tunnel**.
> `PacketTunnelProvider.swift` and `BifrostVpnService.kt` currently forward raw
> IP packets over a plain `UDP` socket with **no WireGuard/OpenVPN handshake, no
> encryption, and no authentication**. They MUST NOT be enabled by default or
> presented to users as secure. They exist as a structural starting point only.

### What is wired up in this change

- **`app.json`**
  - iOS `entitlements`: `com.apple.developer.networking.networkextension`
    = `["packet-tunnel-provider"]`.
  - Android `permissions`: `FOREGROUND_SERVICE`,
    `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS` (plus existing
    `INTERNET` / `ACCESS_NETWORK_STATE`).
  - Registers the config plugin `./plugins/withBifrostVpn`.
- **`plugins/withBifrostVpn.js`** — on `expo prebuild` / EAS Build, injects the
  Android `<service android:name="com.bifrost.vpn.BifrostVpnService">` with the
  system-held `android:permission="android.permission.BIND_VPN_SERVICE"`, the
  `android.net.VpnService` intent filter, and the `specialUse` foreground-service
  subtype property. (`BIND_VPN_SERVICE` is a signature permission declared on the
  `<service>`, **not** requested via `<uses-permission>`.)
- **`eas.json`** — `development` / `preview` / `production` build profiles.
- **`src/native/BifrostVpn.ts`** — typed JS bridge. `isNativeVpnAvailable()`
  returns `false` whenever the native module is not linked (Expo Go, the current
  scaffold, web), and every method degrades to a safe no-op / clear error so the
  app keeps building and running against the REST VPN flow.

### What is still required (DEFERRED — needs platform toolchains)

These steps cannot be completed or validated in this environment (they need the
Xcode/iOS Network Extension toolchain, the Android NDK, a paid Apple Developer
account for the NE entitlement, and a real Bifrost server to test against):

1. **Replace the placeholder data path with a real secure tunnel.** Options:
   - `wireguard-go` compiled for mobile via `gomobile bind` (reuses the Go
     WireGuard backend already in `internal/backend`), **or**
   - `WireGuardKit` (iOS) + `wireguard-android` (Android) libraries, **or**
   - an OpenVPN library. Until this lands, do not enable the native path.
2. **iOS Network Extension target.** A config plugin alone cannot add a second
   Xcode target. After `expo prebuild`, add a *Packet Tunnel Provider* extension
   target in Xcode, move `PacketTunnelProvider.swift` into it, configure App
   Groups + the `packet-tunnel-provider` entitlement on **both** the app and the
   extension, and provision matching profiles. Consider a dedicated plugin (e.g.
   an `@config-plugins`-style mod) to automate this in CI.
3. **Native module (`BifrostVpn`).** Implement the `NativeModules.BifrostVpn`
   contract defined in `src/native/BifrostVpn.ts` (`requestPermission`, `start`,
   `stop`, `getStatus`, and the `BifrostVpnStateChanged` event):
   - Android: a `ReactContextBaseJavaModule` that calls `VpnService.prepare()`
     and starts/stops `BifrostVpnService` via intents.
   - iOS: an `RCTBridgeModule` that drives `NETunnelProviderManager`.
4. **Build & validate on real devices** (requires NDK / Xcode / signing):
   ```bash
   npx expo prebuild           # generates ios/ + android/ from config
   eas build --profile development --platform android
   eas build --profile development --platform ios
   ```
5. **Set a real EAS `projectId`** in `app.json` (`extra.eas.projectId`, currently
   a placeholder) via `eas init`.

### Why it's gated off

The bridge defaults to the server-side VPN flow (`selectVpnMode()` returns
`'server'` unless a real native module is linked). This keeps a known-insecure
raw-UDP forwarder from ever running silently. Wiring the UI to the native path
should happen only after step 1 above is complete and validated on-device.

## Useful commands

```bash
npm run doctor              # expo-doctor sanity checks
npx expo prebuild           # generate native projects (applies the config plugin)
eas build --profile preview --platform android
```
