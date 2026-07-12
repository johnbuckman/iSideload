#!/bin/bash
# Discover a paired iOS device on the local mesh WITHOUT mDNS: scan the /24 for the
# lockdown port (62078) by unicast, then confirm identity + lock state by connecting
# with the device's stored pair record. DHCP- and mesh-proof (pure unicast).
#   sweep.sh <udid> [subnet-prefix]     e.g. sweep.sh 00008112-... 192.168.4
set -u
UDID="${1:?usage: sweep.sh <udid> [subnet-prefix]}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="$HERE/idevice_ipprobe"
# Enumerate every host IP in the Mac's actual subnet(s), honoring the real netmask
# (mesh routers often use /22, so a /24 assumption misses most of the network).
# Optional arg 2 overrides with a CIDR (e.g. 192.168.4.0/22).
gen_hosts() {
python3 - "$@" <<'PY'
import sys, ipaddress, subprocess, re
nets=[]
if len(sys.argv)>1 and sys.argv[1]:
    nets=[ipaddress.ip_network(sys.argv[1], strict=False)]
else:
    out=subprocess.run(["ifconfig"],capture_output=True,text=True).stdout
    for ip,hexmask in re.findall(r'inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)',out):
        if not (ip.startswith(("192.168.","10.","172."))): continue
        bits=bin(int(hexmask,16)).count("1")
        nets.append(ipaddress.ip_network(f"{ip}/{bits}",strict=False))
seen=set()
for n in nets:
    if n.num_addresses>4096: continue   # safety cap
    for h in n.hosts():
        s=str(h)
        if s not in seen: seen.add(s); print(s)
PY
}
HOSTS=$(gen_hosts "${2:-}")
CNT=$(echo "$HOSTS" | grep -c .)
echo "sweeping $CNT hosts across the local subnet(s) for :62078 (unicast, no mDNS)…"
# fast parallel port scan (128 at a time)
OPEN=$(echo "$HOSTS" | ( n=0; while read ip; do
    ( nc -z -G 1 "$ip" 62078 2>/dev/null && echo "$ip" ) &
    n=$((n+1)); (( n % 128 == 0 )) && wait
  done; wait ))
OPEN=$(echo "$OPEN" | grep -v '^$' | sort -t. -k3,3n -k4,4n)
[ -n "$OPEN" ] || { echo "no hosts with :62078 open"; exit 1; }
echo "hosts with lockdown open:"; echo "$OPEN" | sed 's/^/  /'
echo "identifying ${UDID} …"
for ip in $OPEN; do
  OUT=$("$PROBE" "$UDID" "$ip" 2>/dev/null)
  RC=$?
  # a matching pair record → handshake succeeds → REACHABLE (wrong device → UNREACHABLE)
  if echo "$OUT" | awk -F'\t' '$2=="REACHABLE"{exit 0} END{exit 1}'; then
    echo ">>> FOUND $UDID at $ip : $OUT"
    exit $RC
  fi
done
echo "device $UDID not found among open hosts"
exit 1
