# wc-uniffi

`wc-uniffi` exposes the Rust single-session WalletConnect wallet client to Android
through UniFFI-generated Kotlin bindings. Rust remains the protocol authority:
Kotlin receives stable review JSON for wallet UX and policy, while Rust retains
the opaque pending messages needed to approve, reject, respond, extend, or
disconnect without reconstructing protocol state.

## Scope

This crate is intentionally scoped to Green's current Android target:

- one active WalletConnect session and one active pairing at a time
- no persistence or process-restore contract
- wallet-side proposal, authenticate, session request, session update, session
  extend, session delete, ping, and event handling
- outbound session namespace updates and session events
- typed Bitcoin result validation before successful responses are published
- explicit generic JSON response support for non-Bitcoin methods

Persistence/restore and multi-session/multi-pairing support are not production
requirements for this integration slice.

## Generated Kotlin

Kotlin bindings are generated with the checked-in `uniffi.toml`:

- package: `com.blockstream.walletconnect`
- native library: `libwc_uniffi.so`
- Android cleaner support enabled
- immutable Kotlin record fields
- opaque `WcClientConfig` object, so the relay auth seed is not exposed through
  a generated Kotlin data-class `toString()`

Install the matching bindgen once:

```sh
cargo install uniffi --version 0.31.2 --features cli --bin uniffi-bindgen --locked
```

Then generate bindings:

```sh
just wc_uniffi_kotlin_bindings
```

The generated file is written under
`target/wc-uniffi-kotlin/com/blockstream/walletconnect/wc_uniffi.kt`.

## Android Build

Green production flavors currently package only `armeabi-v7a` and `arm64-v8a`.
Build those ABIs with:

```sh
just wc_uniffi_android_release
```

Release recipes strip unneeded native symbols with `llvm-strip` by default. Set
`ANDROID_STRIP=/path/to/llvm-strip` if the strip binary is not on `PATH`.

Debug emulator ABIs can be built when needed with:

```sh
just wc_uniffi_android_debug_all
```

Debug shared libraries are written under `target/wc-uniffi-android-debug/`.
For checking app-source packaging across devices and emulators with optimized
native code, build all release ABIs with:

```sh
just wc_uniffi_android_release_all
```

The production shared libraries are written to:

- `target/wc-uniffi-android/armeabi-v7a/libwc_uniffi.so`
- `target/wc-uniffi-android/arm64-v8a/libwc_uniffi.so`

The all-ABI release recipe writes optimized, stripped copies under:

- `target/wc-uniffi-android-release-all/armeabi-v7a/libwc_uniffi.so`
- `target/wc-uniffi-android-release-all/arm64-v8a/libwc_uniffi.so`
- `target/wc-uniffi-android-release-all/x86/libwc_uniffi.so`
- `target/wc-uniffi-android-release-all/x86_64/libwc_uniffi.so`

## Green Integration Points

For `/Volumes/Somebody/Desktop/Simp/green_android`, place the generated Kotlin
binding in Android-only source, for example:

```text
data/src/androidMain/kotlin/com/blockstream/walletconnect/wc_uniffi.kt
```

Place the production native libraries in Android JNI assets, for example:

```text
data/src/androidMain/jniLibs/armeabi-v7a/libwc_uniffi.so
data/src/androidMain/jniLibs/arm64-v8a/libwc_uniffi.so
```

If the app-source tree needs emulator support without rebuilding native code,
copy the all-ABI release output instead:

```text
data/src/androidMain/jniLibs/armeabi-v7a/libwc_uniffi.so
data/src/androidMain/jniLibs/arm64-v8a/libwc_uniffi.so
data/src/androidMain/jniLibs/x86/libwc_uniffi.so
data/src/androidMain/jniLibs/x86_64/libwc_uniffi.so
```

Green should import the checked-in facade rather than generated UniFFI classes
directly:

```text
data/src/androidMain/kotlin/com/blockstream/data/walletconnect/WalletConnectClient.kt
```

The generated binding uses JNA. Green already has `jna = "5.18.1"` in its
version catalog and app R8 rules for JNA. The Android source set that owns the
generated binding should depend on the Android artifact:

```kotlin
implementation("${libs.jna.get()}@aar")
```

## Wallet Flow

1. Generate and store a relay auth seed with `wcGenerateRelayAuthSeedHex()`.
2. Construct `WcClientConfig` with the Reown project ID, seed, subject, and
   optional relay tuning.
3. Call `WcClient.connect(config)`.
4. Call `pair(uri, origin)` for QR or deep-link WalletConnect URIs.
5. Poll `nextEvent()` on a background dispatcher.
6. Render `reviewJson` for proposal, authenticate, session request, and session
   update decisions. Treat Verify and redirect review fields as wallet UX
   inputs, not diagnostics.
7. If Android resolves Verify context externally, pass the resolved
   `verify.context` JSON to `rememberVerifyContext()` or to the approve/respond
   method's `verifyContextJson` argument. Rust will bind that context to the
   pending approval before publishing.
8. Approve or reject with the matching topic and request id. Authenticate
   approvals require signed CACAO JSON and may include session capabilities when
   the wallet grants an authenticated session.
9. For Bitcoin requests, prefer `respondBitcoinRequestSuccessJson()` so Rust
   validates method-specific result shape before publishing.
10. Use `updateSession()` when wallet-selected accounts/methods/events change,
   and `emitSessionEvent()` with typed `SessionEventParams` JSON for account or
   address change notifications.
11. Call `disconnect()` for wallet-initiated session delete and `shutdown()` when
   the wallet runtime is intentionally stopped.

Do not log full review JSON, session JSON, decrypted params, accounts,
signatures, PSBTs, or relay auth seeds in production. These values are present
for wallet policy and confirmation UX only.

## Verification

Focused local checks:

```sh
just wc_uniffi_check
just wc_uniffi_test
just wc_uniffi_kotlin_bindings
just wc_uniffi_android_release
```

Workspace-level checks remain:

```sh
cargo test --workspace --locked
cd tools/js-harness && bun run check
```
