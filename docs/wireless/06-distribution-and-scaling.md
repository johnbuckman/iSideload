# 6. Distribution & scaling

## The key rule: the device cap follows the account that signs

- When **each user signs with their own account** (free *or* paid), each user registers
  only **their own** device under **their own** account → **the distributor has no
  central device cap.** Scales to unlimited users (the AltStore model).
- The **"100 devices/year" cap only exists when *you* centralize** everything under one
  paid account — it's a property of **Ad-Hoc** distribution, not of iOS or of free IDs.

## The models, side by side

| Model | Who signs | Validity | Cable-free (OTA)? | Device cap on you | Cost |
|---|---|---|---|---|---|
| **Free ID, per user** | each user, own free Apple ID | **7 days** | ❌ (dev signing can't OTA) → USB | none | $0/user |
| **Paid ID, per user** | each user, own $99 account | **1 year** | ✅ possible (their own Ad-Hoc) | none | **$99/user/yr** |
| **Your one paid account** | you, centrally (Ad-Hoc) | 1 year | ✅ | **100/yr** | $99 total |

Takeaways:
- "Unlimited devices" comes from **decentralizing the account** (each user brings their
  own). Free → unlimited but 7-day + USB. Each user's own paid → unlimited **and** 1-year
  **and** optionally cable-free — you just don't pay for it, they do ($99/yr each).
- The only model that caps you at 100 is the one where **you** foot a single $99 and sign
  for everyone (the central Ad-Hoc / OTA path).
- **You cannot have both "unlimited" and "cable-free central"** — unlimited needs
  per-user accounts (free = no OTA; paid = $99/user), and central OTA is Ad-Hoc (capped
  at 100). This is an Apple-rules constraint, not a limitation of the tool.

## Scaling to thousands (beyond the sideload models)

If you need many more than ~100 devices with low per-user friction, you're really
choosing a **different distribution channel**, and it depends on whether the app can pass
review:

| Channel | Devices | Needs | Notes |
|---|---|---|---|
| **TestFlight** | up to **10,000** external testers | (light) beta review; re-upload build every 90 days | Public invite link, no UDID registration, installs via TestFlight app |
| **App Store** | unlimited | full App Review | The real answer for scale |
| **Enterprise Program ($299/yr)** | unlimited, no UDID registration, OTA | genuine **internal-employee** use only | **Do not use for customers** — Apple revokes certs that distribute publicly, instantly killing every install; also hard to obtain now |
| **EU Web Distribution / alt marketplaces** (iOS 17.4/17.5+) | large | eligibility thresholds/fees, notarization | **EU-only** |
| **MDM / supervised** | unlimited managed devices | customers enroll/supervise their devices | Unrealistic for consumers |

## Strategic read for Decent Espresso

- The **Tcl/undroidwish apps** (de1app/iWish) almost certainly **can't pass App Review**
  (non-standard runtime, self-updating/downloading code) — which is exactly *why* they're
  sideloaded. So TestFlight/App Store are not open to them.
- **Sideload + OTA (this research)** is excellent for those apps at **≤100 devices**
  (your own machines, betas, small batches), or a few hundred across multiple paid
  accounts, or unlimited via the **per-user free/paid** model (each owner signs on their
  own machine).
- **Real scale (thousands) means a *reviewable* app** — the **Flutter app** (reaprime) on
  **TestFlight (10k)** or the **App Store (unlimited)**. That's the sanctioned path past
  the low hundreds.
- So the two tracks coexist: keep the Tcl app on sideload/OTA rails for the
  enthusiast/small-batch case; treat the Flutter app + App Store/TestFlight as the answer
  whenever you need to be on many more than 100 machines.
