# 2. Direct-IP install (lockdown/AFC by IP, bypassing mDNS)

The first wireless approach: keep using the normal lockdown → AFC upload →
`installation_proxy` install path, but reach the device **by IP** instead of relying
on usbmux's Bonjour/mDNS discovery.

## Why discovery had to be bypassed

Apple's `usbmuxd` discovers Wi-Fi devices via **Bonjour/mDNS** (`_apple-mobdev2._tcp`).
On the Eero **mesh**, multicast/mDNS does not reliably propagate between AP nodes, so
`idevice_id -n` never listed the target device even though it was on the LAN and its
lockdown port (62078) was open and reachable by **unicast**. A Bonjour proxy record
(`dns-sd -P`) did not work — usbmuxd needs the device's genuine advertisement + the
link-local address it encodes, which the mesh doesn't carry across segments.

Conclusion: **discover/target by unicast IP**, not mDNS.

## The enabling fact

- Device reachable by unicast: `nc -z <ip> 62078` succeeds even when `idevice_id -n`
  shows nothing.
- The **pair record** exists on disk (`/var/db/lockdown/<UDID>.plist`) and is looked up
  **by UDID**, so a by-IP connection can complete the lockdown SSL handshake with no
  "discovery" at all.

## The tooling

libimobiledevice connects to a *network* device by `socket_connect_addr()` to a stored
`sockaddr` — usbmux only supplies that address and the pair record. So we can feed it
the IP directly. We **patched libimobiledevice** to add a clean entry point:

```c
idevice_error_t idevice_new_network(idevice_t *device, const char *udid, const char *ip);
// builds a CONNECTION_NETWORK idevice_t whose conn_data is a sockaddr_in for <ip>
```

Tools built on top (see file 08):
- **`idevice_ipinstall <udid> <ip> <ipa>`** — lockdown handshake by IP → AFC upload to
  `PublicStaging` → `instproxy_install`.
- **`idevice_ipprobe <udid> <ip>`** — handshake + AFC directory read → reports
  `REACHABLE|UNREACHABLE` and `UNLOCKED|LOCKED` + device name.
- **`sweep.sh <udid>`** — netmask-aware unicast scan of the whole local subnet for
  `:62078`, then identify each host by trying the stored pair record. DHCP- & mesh-proof.

## Gotchas discovered (in order)

### a. usbmux hides a network device while it's on USB
While a device is connected via USB, macOS usbmuxd does **not** expose a separate
network entry, so you must physically unplug (or connect network-only) to exercise the
Wi-Fi path. A forced network-only lookup fails instantly while USB is attached.

### b. TLS-version cap for a hand-built device (AFC error 34 = `AFC_E_SSL_ERROR`)
`idevice_connection_enable_ssl()` **forces max TLS 1.0** when
`connection->device->version < IDEVICE_DEVICE_VERSION(10,0,0)`. A hand-built device
starts at `version = 0`, so the **service** (AFC) SSL handshake was capped at TLS 1.0
and iOS 16–26 reject it. The lockdown handshake auto-updates `device->version` from
`ProductVersion`; the fix in `idevice_new_network` / the library path is to let that
happen (or set a modern version). *(This was an early red herring on the mesh — see (e).)*

### c. Correct netmask matters — the mesh is a /22, not a /24
The Eero hands out `192.168.4.0/22` (mask `0xfffffc00`), spanning `.4`–`.7`. A `/24`-only
sweep misses ~¾ of the network — the target jumped from `192.168.4.86` to
`192.168.5.129` after a MAC rotation and a `/24` sweep couldn't find it. `sweep.sh`
reads the real netmask (via Python `ipaddress`) and scans the full range (~1022 hosts in
~10 s).

### d. The device must be **currently unlocked** for AFC (data-partition) ops
Controlled A/B: **locked** → the AFC service resets the TLS connection → install fails;
**unlocked** → AFC opens → install succeeds. So timing matters.
- **The reliable lock detector is whether the AFC service opens** (reset = locked). It's
  cheap (before any upload).
- **`GetProhibited` on a lockdown `GetValue` (e.g. `DeviceClass`) is NOT a lock signal** —
  it appears in *both* states over Wi-Fi. Don't use it.

### e. The real Eero blocker: inbound dynamic-high-port TCP is actively reset
The decisive finding. With the device **provably awake and unlocked** (its beacon was
visibly pinging), on the **same /24** as the Mac, freshly rebooted + USB-retrusted:
- lockdown on the fixed port **62078 works** (TLS 1.2 negotiates fine),
- but the **AFC service on its dynamic high port** (e.g. 53012) gets
  `Connection reset by peer` — an **active RST**, not a timeout — every time.

`62078` (well-known) works while dynamic high ports die → the signature of **Eero
client/port isolation on non-standard ports**. It is **not** lock, sleep, or escrow:
a direct-IP AFC install *did* succeed once early on (officepad `.86`, 76 MB, 13.9 s) and
on an iPhone 14 Pro Max over Wi-Fi, so it's **environment-dependent/intermittent**, not
impossible.

### f. Escrow bag & reboots
A device reboot can invalidate the pairing **escrow bag** (needed for data-partition
access); a **USB reconnect while unlocked** refreshes it. We saw AFC keep failing after
a reboot+USB-retrust — but that turned out to be (e), the Eero reset, not escrow (USB
install worked perfectly ~3 s throughout).

## Verdict

Direct-IP install is a real, working mechanism (proven multiple times) and is **free-tier
compatible + fully silent** — but it depends on: device awake+unlocked, `EnableWifiConnections`
on, and a network that doesn't isolate inbound dynamic ports. On a well-behaved network
it's great; on a hostile mesh it's unreliable. Treat it as the opportunistic rung of the
ladder, not the guarantee. The robust wireless path is OTA (file 04), because it only
uses *outbound* connections from the device.
