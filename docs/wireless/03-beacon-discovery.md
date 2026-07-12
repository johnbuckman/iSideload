# 3. Beacon discovery (device → Mac), and the loopback wall

## The idea

Instead of the Mac *scanning* for devices (which the mesh breaks), have a small piece of
code **on the device ping the Mac** on launch. The Mac learns the device's IP from the
packet — discovery with **zero scanning**, and it works even under DHCP churn because
the device reports its own current address.

## What we built and proved

- A minimal **iOS beacon app** (`scratchpad/beacon/`, SwiftUI/UIKit): on launch it
  sends a UDP datagram every second to the Mac (`NWConnection`, unicast to the Mac's IP
  and port 51234) with the device name + a sequence counter, and shows a live counter
  on screen.
- Signed for the device, installed over USB, and run with USB unplugged.
- **Result:** the Mac's UDP listener received `BEACON FROM 192.168.4.86 … seq=N` every
  second. **Device→Mac UDP sails straight through the Eero mesh** — the exact network
  that resets inbound high-port TCP. The direction the device *initiates* is not
  isolated.

So **discovery is solved**: the Mac learns the device's IP with no scanning, DHCP-proof,
mesh-proof.

## The wall: an iOS app cannot reach its own `lockdownd`

The tempting next step was to have the device do more itself — either install its own
apps, or act as a relay so the Mac could reach the device's services through the
device-initiated connection. Both require the on-device app to talk to the device's own
`lockdownd`. **It can't.**

We extended the beacon to TCP-probe three endpoints and report the result:
- `127.0.0.1:62078` (lockdownd via loopback)
- `<own-wifi-ip>:62078` (lockdownd via the device's own address)
- `127.0.0.1:27015` (a usbmux-style port)

Over 80+ seconds all three stayed **`pending`** — `NWConnection` never reached `.ready`
nor cleanly `.failed`; it sat in `.waiting` (SYN unanswered/refused). The self-IP probe
hung even though the *Mac* reaches that same `IP:62078` fine. **Conclusion: the iOS
sandbox blocks apps from reaching `lockdownd`.**

This kills, via plain sockets:
- **on-device self-install** (app → localhost lockdownd/AFC/instproxy), and
- **the app-relay reverse-tunnel** (relay Mac ↔ localhost:62078).

This is exactly why SideStore/AltStore carry a heavyweight **pairing-file + WireGuard
VPN + minimuxer** stack — the VPN creates an on-device network path to `lockdownd`
precisely *because* the direct one is blocked. See file 07 for that research; it
directly validates this spike.

## The asymmetry that shaped the final design

| Direction | Works on the Eero mesh? |
|---|---|
| Device → Mac (UDP beacon) | ✅ |
| Mac → device, port 62078 (lockdown) | ✅ |
| Mac → device, dynamic high port (AFC install) | ❌ reset |
| App → device's own lockdownd (loopback) | ❌ blocked by sandbox |

The only universally-working directions are **outbound from the device**. That is the
insight that points at **OTA** (file 04): let the device *pull* a signed app from the
Mac over outbound HTTPS and let the OS install it — nothing ever connects *into* the
device, and no app needs to reach lockdownd.

## Where the beacon still fits

Even though it can't drive the install itself, the beacon remains valuable as the
**discovery layer**: it tells the Mac "device X is at IP Y, right now," which the Mac can
use to (a) attempt a direct-IP install when the network allows, or (b) tie an incoming
web request to a specific device for the OTA portal (file 05).
