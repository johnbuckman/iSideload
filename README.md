# iSideload

A small **macOS menu-bar app** that installs and keeps iOS apps signed on your
devices using a **free Apple ID** — a lean, self-contained alternative to
AltStore/SideStore that signs on the Mac.

> **New to sideloading?** Read the **[full step-by-step guide](docs/GUIDE.md)** —
> what to do on your iPhone/iPad, what to download, and the real benefits & limits.

## What it does

- **Sign in with one or more Apple IDs** (free or paid). Login, 2-factor
  (including SMS for accounts with no trusted device), and the Apple developer
  provisioning are all handled for you.
- **Install** an app from an AltStore-format **source URL**, a local **`.json`**
  catalog, or a single **`.ipa` / `.app`** file.
- Apps are signed with a **SHA-256 CodeDirectory via [zsign]** (the format iOS
  16–26 accept) using Apple's `codesign`-equivalent path, then installed over the
  lockdown/`usbmux` protocol.
- **Keeps apps alive**: a background agent re-signs and reinstalls before the
  7-day free-provisioning expiry — on a timer and whenever you plug a device in.
- **Manage everything from the menu bar**: multiple accounts (each free ID gives
  3 app slots), which apps are installed on which device, when each expires, a
  per-app **Refresh**, and a **–** that uninstalls an app and frees its slot.

Free Apple IDs (create one at <https://icloud.com>) can install **3 apps**; a
$99/year Apple Developer subscription removes that limit and extends signing to
one year.

## Build

```
swift build --product InstallerApp     # the menu-bar app
swift build --product Provision         # the CLI (install / refresh)
```

`./bundle-app.sh` builds and bundles the menu-bar app into `iSideload.app`.
Installing to a device requires [`pymobiledevice3`](https://github.com/doronz88/pymobiledevice3)
(`pip install pymobiledevice3`).

## Credits & license

Built on **[AltSign]** from the **[AltStore]** / **[SideStore]** projects
(© Riley Testut and contributors), which are licensed **AGPL-3.0**. Because this
is a derivative work, iSideload is likewise licensed under the **GNU Affero
General Public License v3.0** — see [`LICENSE`](LICENSE).

The signer is **[zsign]** by zhlynn, included under the **MIT License**
(see [`Dependencies/zsign`](Dependencies/zsign)).

[AltSign]: https://github.com/SideStore/AltSign
[AltStore]: https://github.com/altstoreio/AltStore
[SideStore]: https://github.com/SideStore/SideStore
[zsign]: https://github.com/zhlynn/zsign
