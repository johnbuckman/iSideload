// SideloaderKit — shared provisioning + signing + install pipeline for iSideload.
// Handles: local Anisette, session persistence, keychain password (for unattended
// refresh), AltStore-format source parsing + IPA download, the provision→sign→
// install flow for any app, tracking installed apps, and a 7-day refresh.
import Foundation
import AltSign
import SwiftBridge
import CryptoKit
import Security

public enum SideErr: LocalizedError {
    case fail(String)
    public var errorDescription: String? { if case .fail(let s) = self { return s }; return nil }
}

public func cont<T>(_ body: (@escaping (T?, Error?) -> Void) -> Void) async throws -> T {
    try await withCheckedThrowingContinuation { c in
        body { value, error in
            if let value { c.resume(returning: value) }
            else { c.resume(throwing: error ?? SideErr.fail("nil result")) }
        }
    }
}

let iSideloadSupportDir = NSString(string: "~/Library/Application Support/iSideload").expandingTildeInPath

// MARK: - Local Anisette (AOSKit / AuthKit)

public enum Anisette {
    private static let loaded: Bool = {
        dlopen("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit", RTLD_NOW)
        dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_NOW)
        return true
    }()
    private static func akDevice() -> AnyObject? {
        guard let cls = NSClassFromString("AKDevice") else { return nil }
        return (cls as AnyObject).perform(NSSelectorFromString("currentDevice"))?.takeUnretainedValue()
    }
    private static func otpHeaders() -> [String: String]? {
        guard let cls = NSClassFromString("AOSUtilities") else { return nil }
        let r = (cls as AnyObject).perform(NSSelectorFromString("retrieveOTPHeadersForDSID:"), with: "-2")
        return r?.takeUnretainedValue() as? [String: String]
    }
    private static func sha256Upper(_ s: String) -> String {
        SHA256.hash(data: Data(s.utf8)).map { String(format: "%02X", $0) }.joined()
    }
    public static func fresh() -> ALTAnisetteData? {
        _ = loaded
        guard let otp = otpHeaders(), let md = otp["X-Apple-MD"], let mdm = otp["X-Apple-MD-M"],
              let dev = akDevice() else { return nil }
        let desc = (dev.value(forKey: "serverFriendlyDescription") as? String) ?? "<Mac> <macOS;26.2;25C56> <com.apple.AuthKit/1>"
        let devUUID = (dev.value(forKey: "uniqueDeviceIdentifier") as? String) ?? UUID().uuidString
        let luUUID = (dev.value(forKey: "localUserUUID") as? String) ?? UUID().uuidString
        let serial = (dev.value(forKey: "serialNumber") as? String) ?? "0"
        return ALTAnisetteData(machineID: mdm, oneTimePassword: md, localUserID: sha256Upper(luUUID),
                               routingInfo: 17106176, deviceUniqueIdentifier: devUUID, deviceSerialNumber: serial,
                               deviceDescription: desc, date: Date(), locale: .current, timeZone: .current)
    }
}

// MARK: - Account persistence (multiple Apple IDs; each free ID = 3 app slots)

public struct AccountRecord: Codable, Identifiable, Sendable {
    public var dsid, authToken, appleID, identifier, firstName, lastName: String
    public var teamType: Int = -1      // ALTTeamType raw: 3=free, 1/2=paid
    public var teamName: String = ""
    public var id: String { appleID }
    public var displayName: String {
        let n = "\(firstName) \(lastName)".trimmingCharacters(in: .whitespaces)
        return n.isEmpty ? appleID : "\(n) (\(appleID))"
    }
    public var isPaid: Bool { teamType == 1 || teamType == 2 }
    public var validity: String {
        switch teamType {
        case 3: return "Free · apps expire after 7 days"
        case 1, 2: return "Paid · apps last 1 year"
        default: return ""
        }
    }
}

public enum AccountStore {
    static let path = iSideloadSupportDir + "/accounts.json"
    public static func records() -> [AccountRecord] {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let list = try? JSONDecoder().decode([AccountRecord].self, from: d) else { return [] }
        return list
    }
    static func write(_ list: [AccountRecord]) {
        try? FileManager.default.createDirectory(atPath: iSideloadSupportDir, withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(list) { try? d.write(to: URL(fileURLWithPath: path)) }
    }
    public static func add(account: ALTAccount, session: ALTAppleAPISession) {
        var list = records().filter { $0.appleID != account.appleID }
        list.append(AccountRecord(dsid: session.dsid, authToken: session.authToken, appleID: account.appleID,
                                  identifier: account.identifier, firstName: account.firstName, lastName: account.lastName))
        write(list)
    }
    public static func remove(_ appleID: String) {
        write(records().filter { $0.appleID != appleID })
        Keychain.clear(appleID)
        CertStore.clear(appleID)
    }
    public static func setTeam(_ appleID: String, type: Int, name: String) {
        var list = records()
        if let i = list.firstIndex(where: { $0.appleID == appleID }) {
            list[i].teamType = type; list[i].teamName = name; write(list)
        }
    }
    /// Reconstruct (account, session) with a FRESH anisette (durable creds are dsid+authToken).
    public static func session(for appleID: String) -> (ALTAccount, ALTAppleAPISession)? {
        guard let r = records().first(where: { $0.appleID == appleID }), let anisette = Anisette.fresh() else { return nil }
        let account = ALTAccount()
        account.appleID = r.appleID; account.identifier = r.identifier
        account.firstName = r.firstName; account.lastName = r.lastName
        return (account, ALTAppleAPISession(dsid: r.dsid, authToken: r.authToken, anisetteData: anisette))
    }
    public static var appleIDs: [String] { records().map(\.appleID) }
}

// MARK: - Keychain (Apple-ID password, so the refresh daemon can re-auth unattended)

public enum Keychain {
    private static let service = "com.decent.isideload.appleid"
    public static func savePassword(_ password: String, for appleID: String) {
        let acct = appleID.data(using: .utf8)!, pw = password.data(using: .utf8)!
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: appleID]
        SecItemDelete(base as CFDictionary)
        var add = base; add[kSecValueData as String] = pw; _ = acct
        SecItemAdd(add as CFDictionary, nil)
    }
    public static func password(for appleID: String) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: appleID,
                                kSecReturnData as String: true,
                                kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    public static func clear(_ appleID: String) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                       kSecAttrService as String: service,
                       kSecAttrAccount as String: appleID] as CFDictionary)
    }
}

// MARK: - Certificate persistence (reuse ONE cert per account so re-signing one app
// doesn't invalidate the account's other apps — a free ID has only one cert)

public enum CertStore {
    static func path(_ appleID: String) -> String { iSideloadSupportDir + "/cert-\(Sideloader.sanitize(appleID)).json" }
    public static func save(_ cert: ALTCertificate, for appleID: String) {
        guard let data = cert.data, let key = cert.privateKey else { return }
        let obj: [String: String] = ["serial": cert.serialNumber, "data": data.base64EncodedString(), "key": key.base64EncodedString()]
        try? FileManager.default.createDirectory(atPath: iSideloadSupportDir, withIntermediateDirectories: true)
        guard let d = try? JSONSerialization.data(withJSONObject: obj) else { return }
        let p = path(appleID)
        try? d.write(to: URL(fileURLWithPath: p))
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: p)
    }
    public static func load(for appleID: String) -> ALTCertificate? {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: path(appleID))),
              let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: String],
              let ds = obj["data"], let ks = obj["key"],
              let data = Data(base64Encoded: ds), let key = Data(base64Encoded: ks),
              let cert = ALTCertificate(data: data) else { return nil }
        cert.privateKey = key
        return cert
    }
    public static func clear(_ appleID: String) { try? FileManager.default.removeItem(atPath: path(appleID)) }
}

// MARK: - AltStore-format source + tracked apps

public struct SourceApp: Codable, Identifiable, Sendable {
    public var name: String
    public var bundleIdentifier: String
    public var downloadURL: String
    public var version: String?
    public var localizedDescription: String?
    public var iconURL: String?
    public var id: String { bundleIdentifier }
    enum CodingKeys: String, CodingKey { case name, bundleIdentifier, downloadURL, version, localizedDescription, iconURL }
}
struct AltSource: Codable { var name: String?; var apps: [SourceApp] }

public struct TrackedApp: Codable, Identifiable {
    public var name: String
    public var origBundleID: String
    public var source: String          // cached .app path (or https/local before caching)
    public var installedBundleID: String
    public var appleID: String = ""    // which account signed it
    public var udid: String = ""       // which device it was installed to
    public var deviceName: String = ""
    public var validityDays: Int = 7   // 7 (free) or 365 (paid)
    public var appIDIdentifier: String = ""   // Apple App-ID id, for deletion
    public var lastInstalled: Double?
    public var id: String { installedBundleID + "@" + udid }
    /// Seconds until the provisioning profile expires (negative = expired).
    public var secondsUntilExpiry: Double? {
        guard let li = lastInstalled else { return nil }
        return (li + Double(validityDays) * 86400) - Date().timeIntervalSince1970
    }
}

public enum Tracked {
    static let path = iSideloadSupportDir + "/tracked.json"
    public static func all() -> [TrackedApp] {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let list = try? JSONDecoder().decode([TrackedApp].self, from: d) else { return [] }
        return list
    }
    static func write(_ list: [TrackedApp]) {
        try? FileManager.default.createDirectory(atPath: iSideloadSupportDir, withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(list) { try? d.write(to: URL(fileURLWithPath: path)) }
    }
    public static func upsert(_ app: TrackedApp) {
        var list = all().filter { !($0.installedBundleID == app.installedBundleID && $0.udid == app.udid) }
        list.append(app)
        write(list)
    }
    public static func remove(installedBundleID: String, udid: String) {
        write(all().filter { !($0.installedBundleID == installedBundleID && $0.udid == udid) })
    }
}

// MARK: - Provision + sign + install

public struct Sideloader {
    @discardableResult
    static func run(_ tool: String, _ args: [String], cwd: URL? = nil, env: [String: String]? = nil) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        if let cwd { p.currentDirectoryURL = cwd }
        if let env { var e = ProcessInfo.processInfo.environment; env.forEach { e[$0] = $1 }; p.environment = e }
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func plistValue(_ key: String, _ plistPath: String) -> String? {
        (try? run("/usr/libexec/PlistBuddy", ["-c", "Print :\(key)", plistPath]))?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    static func sanitize(_ s: String) -> String {
        let r = s.lowercased().unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) }.map(String.init).joined()
        return r.isEmpty ? "app" : r
    }
    static func pythonPath() -> String {
        ["/Library/Frameworks/Python.framework/Versions/3.11/bin/python3",
         "/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
            .first { FileManager.default.isExecutableFile(atPath: $0) } ?? "/usr/bin/python3"
    }

    /// Connected iOS devices as (udid, name). Empty if none / tooling missing.
    public static func connectedDevices() -> [(udid: String, name: String)] {
        let script = NSString(string: "~/iwish/install-tools/listdevices.py").expandingTildeInPath
        guard let out = try? run(pythonPath(), [script]) else { return [] }
        func isUDID(_ s: String) -> Bool {
            s.allSatisfy { $0.isHexDigit || $0 == "-" } && (s.count == 40 || (s.count == 25 && s.contains("-")))
        }
        var seen = Set<String>()
        return out.split(separator: "\n").compactMap { line -> (udid: String, name: String)? in
            let parts = line.split(separator: "\t", maxSplits: 1).map(String.init)
            guard let u = parts.first, isUDID(u), !seen.contains(u) else { return nil }
            seen.insert(u)
            return (u, parts.count > 1 ? parts[1] : u)
        }
    }

    // MARK: source + download

    static func parseSource(_ data: Data) -> [SourceApp] {
        (try? JSONDecoder().decode(AltSource.self, from: data))?.apps ?? []
    }
    public static func fetchSource(_ urlString: String) async throws -> [SourceApp] {
        guard let url = URL(string: urlString) else { throw SideErr.fail("bad source URL") }
        let (data, _) = try await URLSession.shared.data(from: url)
        return parseSource(data)
    }
    /// Read an AltStore-format source from a local .json file.
    public static func loadSourceFile(_ path: String) throws -> [SourceApp] {
        let apps = parseSource(try Data(contentsOf: URL(fileURLWithPath: path)))
        if apps.isEmpty { throw SideErr.fail("no apps found (is this an AltStore-format source JSON?)") }
        return apps
    }
    /// Download + install one app from a parsed source (works regardless of where the catalog came from).
    @discardableResult
    public static func installSourceApp(account: ALTAccount, session: ALTAppleAPISession,
                                        app: SourceApp, iPadUDID: String,
                                        log: @escaping (String) -> Void) async throws -> String {
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("isl-dl-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        let appPath = try await downloadAndUnzipApp(app.downloadURL, into: work, log: log)
        return try await install(account: account, session: session, appPath: appPath.path,
                                 source: app.downloadURL, iPadUDID: iPadUDID, log: log)
    }

    /// Download an IPA and unzip it, returning the path to the .app inside Payload/.
    static func downloadAndUnzipApp(_ urlString: String, into work: URL, log: @escaping (String) -> Void) async throws -> URL {
        guard let url = URL(string: urlString) else { throw SideErr.fail("bad download URL") }
        log("Downloading \(url.lastPathComponent)…")
        let (tmp, _) = try await URLSession.shared.download(from: url)
        let ipa = work.appendingPathComponent("dl.ipa")
        try? FileManager.default.removeItem(at: ipa)
        try FileManager.default.moveItem(at: tmp, to: ipa)
        try run("/usr/bin/unzip", ["-q", ipa.path, "-d", work.path])
        let payload = work.appendingPathComponent("Payload")
        let apps = (try? FileManager.default.contentsOfDirectory(atPath: payload.path)) ?? []
        guard let appName = apps.first(where: { $0.hasSuffix(".app") }) else { throw SideErr.fail("no .app in IPA") }
        return payload.appendingPathComponent(appName)
    }

    // MARK: the pipeline

    /// Provision + sign + install the .app at `appPath`. Records it for refresh.
    /// `source` is what refresh will re-install from (an https IPA URL or the local .app path).
    @discardableResult
    /// Ensure a usable dev cert for the account+team. Reuses a persisted cert if it's still
    /// valid on Apple's side; only rotates (revoke+new) when there isn't one — so re-signing
    /// one app never invalidates the account's other apps.
    static func provisionCertificate(account: ALTAccount, session: ALTAppleAPISession, team: ALTTeam,
                                     log: @escaping (String) -> Void) async throws -> ALTCertificate {
        let api = ALTAppleAPI.sharedAPI
        let existing: [ALTCertificate] = try await cont { api.fetchCertificates(for: team, session: session, completionHandler: $0) }
        if let stored = CertStore.load(for: account.appleID), stored.privateKey != nil,
           existing.contains(where: { $0.serialNumber == stored.serialNumber }) {
            log("reusing existing certificate")
            return stored
        }
        log("issuing a new certificate…")
        for old in existing {
            _ = try? await withCheckedThrowingContinuation { (cc: CheckedContinuation<Bool, Error>) in
                api.revoke(old, for: team, session: session) { ok, e in ok ? cc.resume(returning: true) : cc.resume(throwing: e ?? SideErr.fail("revoke")) }
            }
        }
        let newCert: ALTCertificate = try await cont { api.addCertificate(machineName: "iSideload", to: team, session: session, completionHandler: $0) }
        // submitDevelopmentCSR returns metadata + our key but not cert bytes; fetch list + match by serial.
        let all: [ALTCertificate] = try await cont { api.fetchCertificates(for: team, session: session, completionHandler: $0) }
        guard let cert = all.first(where: { $0.serialNumber == newCert.serialNumber }) else { throw SideErr.fail("new cert not in list") }
        cert.privateKey = newCert.privateKey
        CertStore.save(cert, for: account.appleID)
        return cert
    }

    @discardableResult
    public static func install(account: ALTAccount, session: ALTAppleAPISession,
                               appPath: String, source: String, iPadUDID: String,
                               log: @escaping (String) -> Void) async throws -> String {
        let api = ALTAppleAPI.sharedAPI

        let teams: [ALTTeam] = try await cont { api.fetchTeams(for: account, session: session, completionHandler: $0) }
        guard let team = teams.first(where: { $0.type == .free }) ?? teams.first else { throw SideErr.fail("No teams on this Apple ID") }
        log("Team: \(team.name). Registering iPad…")
        let _: ALTDevice? = try? await cont { api.registerDevice(name: "iPad", identifier: iPadUDID, type: .iPad, team: team, session: session, completionHandler: $0) }

        let cert = try await provisionCertificate(account: account, session: session, team: team, log: log)

        // stage a copy, derive a team-unique bundle id from the app itself
        let fm = FileManager.default
        let work = fm.temporaryDirectory.appendingPathComponent("isideload-\(UUID().uuidString)")
        try fm.createDirectory(at: work, withIntermediateDirectories: true)
        let appCopy = work.appendingPathComponent("app.app")
        try fm.copyItem(at: URL(fileURLWithPath: appPath), to: appCopy)
        let plist = appCopy.appendingPathComponent("Info.plist").path
        let displayName = plistValue("CFBundleDisplayName", plist) ?? plistValue("CFBundleName", plist)
            ?? (appPath as NSString).lastPathComponent.replacingOccurrences(of: ".app", with: "")
        let origBundleID = plistValue("CFBundleIdentifier", plist) ?? "app"
        let bundleID = "com.isideload.\(sanitize(displayName)).\(team.identifier)".lowercased()

        // Cache a copy of the app so future refreshes never need the original json/ipa/URL.
        let cacheDir = iSideloadSupportDir + "/apps"
        try? fm.createDirectory(atPath: cacheDir, withIntermediateDirectories: true)
        let cachePath = cacheDir + "/\(sanitize(bundleID)).app"
        if URL(fileURLWithPath: appPath).resolvingSymlinksInPath().path != URL(fileURLWithPath: cachePath).resolvingSymlinksInPath().path {
            try? fm.removeItem(atPath: cachePath)
            try? fm.copyItem(atPath: appPath, toPath: cachePath)
        }
        log("Creating App ID + profile for \(displayName)…")

        let existing = try await api.fetchAppIDs(for: team, session: session)
        let appID: ALTAppID
        if let f = existing.first(where: { $0.bundleIdentifier == bundleID }) { appID = f }
        else { appID = try await api.addAppID(withName: "\(displayName) (iSideload)", bundleIdentifier: bundleID, team: team, session: session) }
        let profile = try await api.fetchProvisioningProfile(for: appID, deviceType: .iPad, team: team, session: session)
        log("Signing \(displayName)… (profile exp \(profile.expirationDate))")

        try run("/usr/libexec/PlistBuddy", ["-c", "Set :CFBundleIdentifier \(bundleID)", plist])
        let signer = ALTSigner(team: team, certificate: cert)
        _ = try await withCheckedThrowingContinuation { (c: CheckedContinuation<Bool, Error>) in
            _ = signer.signApp(at: appCopy, provisioningProfiles: [profile]) { ok, e in ok ? c.resume(returning: true) : c.resume(throwing: e ?? SideErr.fail("signApp")) }
        }
        log("Installing on iPad…")

        let payload = work.appendingPathComponent("Payload")
        try fm.createDirectory(at: payload, withIntermediateDirectories: true)
        try fm.moveItem(at: appCopy, to: payload.appendingPathComponent("\(sanitize(displayName)).app"))
        let ipa = work.appendingPathComponent("out.ipa")
        try run("/usr/bin/zip", ["-qXr9", ipa.path, "Payload"], cwd: work)

        let py = NSString(string: "~/iwish/install-tools/lockinstall.py").expandingTildeInPath
        let out = try run(pythonPath(), [py, ipa.path], cwd: work, env: ["IWISH_UDID": iPadUDID])
        log("install: \(out.split(separator: "\n").last.map(String.init) ?? out)")
        guard out.contains("INSTALL OK") else { throw SideErr.fail("install failed: \(out.suffix(160))") }

        let deviceName = connectedDevices().first(where: { $0.udid == iPadUDID })?.name ?? ""
        Tracked.upsert(TrackedApp(name: displayName, origBundleID: origBundleID, source: cachePath,
                                  installedBundleID: bundleID, appleID: account.appleID, udid: iPadUDID,
                                  deviceName: deviceName, validityDays: team.type == .free ? 7 : 365,
                                  appIDIdentifier: appID.identifier, lastInstalled: Date().timeIntervalSince1970))
        try? fm.removeItem(at: work)
        return "✅ Installed \(displayName) (\(bundleID))."
    }

    /// Install a chosen app from an AltStore-format source URL.
    @discardableResult
    public static func installFromSource(account: ALTAccount, session: ALTAppleAPISession,
                                         sourceURL: String, bundleIdentifier: String, iPadUDID: String,
                                         log: @escaping (String) -> Void) async throws -> String {
        let apps = try await fetchSource(sourceURL)
        guard let app = apps.first(where: { $0.bundleIdentifier == bundleIdentifier }) ?? apps.first else { throw SideErr.fail("app not found in source") }
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("isideload-dl-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        let appPath = try await downloadAndUnzipApp(app.downloadURL, into: work, log: log)
        return try await install(account: account, session: session, appPath: appPath.path,
                                 source: app.downloadURL, iPadUDID: iPadUDID, log: log)
    }

    /// Install from a local .ipa (or .app) file.
    @discardableResult
    public static func installFromIPA(account: ALTAccount, session: ALTAppleAPISession,
                                      filePath: String, iPadUDID: String,
                                      log: @escaping (String) -> Void) async throws -> String {
        if filePath.hasSuffix(".app") {
            return try await install(account: account, session: session, appPath: filePath, source: filePath, iPadUDID: iPadUDID, log: log)
        }
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("isl-ipa-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        try run("/usr/bin/unzip", ["-q", filePath, "-d", work.path])
        let payload = work.appendingPathComponent("Payload")
        let apps = (try? FileManager.default.contentsOfDirectory(atPath: payload.path)) ?? []
        guard let appName = apps.first(where: { $0.hasSuffix(".app") }) else { throw SideErr.fail("no .app inside the IPA") }
        return try await install(account: account, session: session,
                                 appPath: payload.appendingPathComponent(appName).path,
                                 source: filePath, iPadUDID: iPadUDID, log: log)
    }

    /// Free vs paid team info for an account (for showing 7-day vs 1-year).
    public static func accountTeamInfo(account: ALTAccount, session: ALTAppleAPISession) async -> (type: Int, name: String)? {
        guard let teams: [ALTTeam] = try? await cont({ ALTAppleAPI.sharedAPI.fetchTeams(for: account, session: session, completionHandler: $0) }),
              let team = teams.first(where: { $0.type == .free }) ?? teams.first else { return nil }
        return (team.type.rawValue, team.name)
    }

    /// Re-sign + (WiFi/USB) re-install one tracked app on its device.
    @discardableResult
    public static func refreshOne(_ t: TrackedApp, log: @escaping (String) -> Void) async throws -> String {
        guard let (account, session) = AccountStore.session(for: t.appleID) else { throw SideErr.fail("account \(t.appleID) not signed in") }
        if t.source.hasPrefix("http") {
            let work = FileManager.default.temporaryDirectory.appendingPathComponent("isl-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
            let appPath = try await downloadAndUnzipApp(t.source, into: work, log: log)
            return try await install(account: account, session: session, appPath: appPath.path, source: t.source, iPadUDID: t.udid, log: log)
        }
        return try await installFromIPA(account: account, session: session, filePath: t.source, iPadUDID: t.udid, log: log)
    }

    /// Uninstall from the device, delete its App ID (frees a free-account slot), untrack.
    public static func removeApp(_ t: TrackedApp, log: @escaping (String) -> Void) async {
        let py = NSString(string: "~/iwish/install-tools/lockuninstall.py").expandingTildeInPath
        let out = (try? run(pythonPath(), [py, t.installedBundleID], env: ["IWISH_UDID": t.udid])) ?? ""
        log("uninstall: \(out.split(separator: "\n").last.map(String.init) ?? out)")
        if let (account, session) = AccountStore.session(for: t.appleID),
           let teams: [ALTTeam] = try? await cont({ ALTAppleAPI.sharedAPI.fetchTeams(for: account, session: session, completionHandler: $0) }),
           let team = teams.first(where: { $0.type == .free }) ?? teams.first,
           let appIDs = try? await ALTAppleAPI.sharedAPI.fetchAppIDs(for: team, session: session),
           let appID = appIDs.first(where: { $0.identifier == t.appIDIdentifier || $0.bundleIdentifier == t.installedBundleID }) {
            _ = try? await withCheckedThrowingContinuation { (c: CheckedContinuation<Bool, Error>) in
                ALTAppleAPI.sharedAPI.deleteAppID(appID, for: team, session: session) { ok, e in ok ? c.resume(returning: true) : c.resume(throwing: e ?? SideErr.fail("deleteAppID")) }
            }
            log("freed the App ID slot")
        }
        Tracked.remove(installedBundleID: t.installedBundleID, udid: t.udid)
        try? FileManager.default.removeItem(atPath: iSideloadSupportDir + "/apps/\(sanitize(t.installedBundleID)).app")
    }

    // MARK: refresh (7-day)

    /// Re-provision + re-sign + reinstall every tracked app, grouped by the account that
    /// installed it and targeting the device it was installed to. Falls back to a silent
    /// re-auth with the keychain-stored password if an account's session has expired.
    public static func refreshAll(log: @escaping (String) -> Void) async throws {
        let tracked = Tracked.all()
        guard !tracked.isEmpty else { log("nothing to refresh"); return }

        // single-flight lock (timer + connect-trigger can both fire) — ignore stale >15min
        let fm = FileManager.default
        let lock = iSideloadSupportDir + "/refresh.lock"
        if let attrs = try? fm.attributesOfItem(atPath: lock), let mt = attrs[.modificationDate] as? Date,
           Date().timeIntervalSince(mt) < 900 { log("another refresh is running — skipping"); return }
        try? fm.createDirectory(atPath: iSideloadSupportDir, withIntermediateDirectories: true)
        fm.createFile(atPath: lock, contents: nil)
        defer { try? fm.removeItem(atPath: lock) }

        let now = Date().timeIntervalSince1970
        let refreshThreshold = 5.0 * 24 * 3600   // re-sign only when within ~2 days of the 7-day expiry
        let connected = Set(connectedDevices().map { $0.udid })
        let fallbackUDID = connectedDevices().first?.udid ?? ""

        var byAccount: [String: [TrackedApp]] = [:]
        for t in tracked {
            let aid = t.appleID.isEmpty ? (AccountStore.appleIDs.first ?? "") : t.appleID
            byAccount[aid, default: []].append(t)
        }

        for (appleID, apps) in byAccount {
            guard var pair = AccountStore.session(for: appleID) else { log("no saved account for \(appleID) — skipping"); continue }
            // validate session; re-auth via keychain if needed
            do { _ = try await cont { ALTAppleAPI.sharedAPI.fetchTeams(for: pair.0, session: pair.1, completionHandler: $0) } }
            catch {
                log("session for \(appleID) expired — re-authenticating…")
                if let pw = Keychain.password(for: appleID), let anisette = Anisette.fresh() {
                    let res: (ALTAccount, ALTAppleAPISession)? = try? await withCheckedThrowingContinuation { c in
                        ALTAppleAPI.sharedAPI.authenticate(appleID: appleID, password: pw, anisetteData: anisette,
                            verificationHandler: { submit in submit(nil) },   // unattended: can't satisfy 2FA
                            completionHandler: { a, s, e in if let a, let s { c.resume(returning: (a, s)) } else { c.resume(throwing: e ?? SideErr.fail("reauth")) } })
                    }
                    if let r = res { pair = r; AccountStore.add(account: r.0, session: r.1) }
                }
            }
            for t in apps {
                if let li = t.lastInstalled, now - li < refreshThreshold { log("\(t.name) still fresh — skipping"); continue }
                let udid = (!t.udid.isEmpty && connected.contains(t.udid)) ? t.udid : fallbackUDID
                if udid.isEmpty { log("no device connected for \(t.name) — skipping"); continue }
                do {
                    log("refreshing \(t.name) [\(appleID)]…")
                    if t.source.hasPrefix("http") {
                        let work = FileManager.default.temporaryDirectory.appendingPathComponent("isl-\(UUID().uuidString)")
                        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
                        let appPath = try await downloadAndUnzipApp(t.source, into: work, log: log)
                        _ = try await install(account: pair.0, session: pair.1, appPath: appPath.path, source: t.source, iPadUDID: udid, log: log)
                    } else {
                        _ = try await installFromIPA(account: pair.0, session: pair.1, filePath: t.source, iPadUDID: udid, log: log)
                    }
                } catch { log("refresh \(t.name) FAILED: \(error.localizedDescription)") }
            }
        }
    }
}
