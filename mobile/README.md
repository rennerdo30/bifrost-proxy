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
npm test            # node --test (service-layer unit tests)
npm start           # expo start (Expo Go: management UI only, no native VPN)
```

`node_modules/` is gitignored and must be installed locally.

### Tests

`npm test` runs the service-layer unit tests (`src/services/__tests__/`) on
Node's built-in test runner, using Node's TypeScript type stripping. There is
deliberately **no** `jest`/`jest-expo` dependency: the tests cover `api.ts` and
`storage.ts`, which need no renderer.

Two mechanics make that work:

- `scripts/node-test-resolver.mjs` fills in the file extension that Metro would
  otherwise resolve, so app sources keep using plain `./storage` imports.
- `src/services/__tests__/helpers.ts` swaps
  `@react-native-async-storage/async-storage` for an in-memory stand-in and
  stubs `fetch`, recording every request so header, route and body expectations
  can be asserted.

Type stripping is *strip-only*: TypeScript constructs that need code generation
(parameter properties, `enum`, `namespace`) will not load. Avoid them in any file
reachable from a test.

Covered today: `api.ts`, `storage.ts`, `splitTunnelSync.ts` (rule reconciliation
and the replace-semantics policy push), `utils/status.ts`, and `i18n.ts`.

Screen components are not yet covered — that needs React Native Testing Library,
which Expo SDK 55 does not pin.

## Assets

`assets/` holds three distinct images, not three copies of one:

| File | Role | Constraints |
|------|------|-------------|
| `icon.png` | App icon | 1024×1024, opaque, its own rounded-square ground |
| `adaptive-icon.png` | Android adaptive **foreground** | 1024×1024, transparent; artwork stays inside the 66% safe-zone circle because Android masks the rest. The ground comes from `android.adaptiveIcon.backgroundColor` |
| `splash.png` | Launch composition | 1024×1024, transparent, vertically centred; the ground comes from `splash.backgroundColor` |

Baking a background into the adaptive foreground produces a squircle inside a
squircle once Android applies its mask, so keep that file transparent.

## Internationalisation

User-facing strings live in `src/i18n.ts` (English + German) and are read via
`t('key')`. `formatNumber`/`formatDecimal` and the `duration.*` keys keep counts
and durations locale-aware. The catalogue is typed: adding a key to the English
object makes it required in the German one, so a missing translation is a
compile error rather than an English string leaking into a German build.

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
│   ├── services/storage.ts # AsyncStorage persistence (address, token, rules)
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
  - iOS: the Network Extension entitlement is intentionally NOT declared —
    the packet-tunnel extension does not exist yet, and requesting an
    entitlement for a missing extension breaks provisioning. Add
    `com.apple.developer.networking.networkextension =
    ["packet-tunnel-provider"]` when the extension target is real.
  - Android `permissions`: `FOREGROUND_SERVICE`,
    `FOREGROUND_SERVICE_SPECIAL_USE` (plus existing `INTERNET` /
    `ACCESS_NETWORK_STATE`). `POST_NOTIFICATIONS` is deliberately absent —
    nothing in the app posts a notification.
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
5. **Link the project to EAS.** `app.json` carries no `extra.eas.projectId`: the
   project is not linked to an Expo account, and a fabricated placeholder UUID
   was removed because it looked configured while pointing at nothing. Run
   `eas init` in this directory with your own Expo account before the first
   `eas build`; it writes the real `projectId` for you.

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
