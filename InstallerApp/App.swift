// iSideload — lean-AltServer macOS app.
// Multiple Apple accounts (each free ID = 3 app slots), install from an AltStore
// source URL or a local .ipa/.app, pick which account + which connected device.
import SwiftUI
import AltSign
import SwiftBridge
import SideloaderKit
import AppKit
import ServiceManagement
import UniformTypeIdentifiers
import Foundation

// In-app refresh scheduler — replaces the external LaunchAgents. Runs while the
// app is alive in the menu bar: refreshes on device-connect and on a ~2h timer
// (refreshAll is itself expiry-aware + single-flight-locked, so this is cheap).
final class RefreshDaemon {
    static let shared = RefreshDaemon()
    private let q = DispatchQueue(label: "com.decent.isideload.refresh")
    private var seen = Set<String>()
    private var started = false
    private var tickCount = 0

    func start() {
        guard !started else { return }
        started = true
        q.async { [weak self] in
            while true {
                self?.tick()
                Thread.sleep(forTimeInterval: 25)
            }
        }
    }
    private func tick() {
        tickCount += 1
        let devices = Set(Sideloader.connectedDevices().map { $0.udid })   // USB + WiFi-reachable
        let newlyConnected = !devices.subtracting(seen).isEmpty
        seen = devices

        // "Urgent" = an app past 70% of its signing window whose device is reachable right now.
        // Free profiles die at 7 days and only install to an UNLOCKED device, so near expiry we
        // poll every 5 minutes and push the moment the device is reachable (USB or WiFi/unlocked).
        let now = Date().timeIntervalSince1970
        let urgentReachable = Tracked.all().contains { t in
            guard let li = t.lastInstalled else { return false }
            let past70 = (now - li) > 0.7 * Double(t.validityDays) * 86400
            return past70 && devices.contains(t.udid)
        }
        let fiveMinTick = (tickCount % 12 == 0)   // 25s × 12 ≈ 5 min

        if (newlyConnected && !devices.isEmpty) || (fiveMinTick && urgentReachable) {
            Task { try? await Sideloader.refreshAll(log: { print("[iSideload refresh] \($0)") }) }
        }
    }
}

let iSideloadLogPath = (("~/Library/Logs/iSideload.log") as NSString).expandingTildeInPath
func installDiagnosticsLog() {
    freopen(iSideloadLogPath, "a", stdout); freopen(iSideloadLogPath, "a", stderr)
    setvbuf(stdout, nil, _IOLBF, 0); setvbuf(stderr, nil, _IOLBF, 0)
    AltSignLogging.setLogging(true)
    print("\n=== iSideload launched \(Date()) ===")
}

struct DeviceOption: Identifiable { let udid: String; let name: String; var id: String { udid } }
enum InstallKind { case ipa(String), source(SourceApp) }

@MainActor final class AppModel: ObservableObject {
    // accounts
    @Published var accounts: [AccountRecord] = AccountStore.records()
    @Published var tracked: [TrackedApp] = Tracked.all()
    @Published var addingAccount = false

    // login form
    @Published var appleID = ""
    @Published var password = ""
    @Published var code = ""
    @Published var textMeCode = false
    enum LoginStage: Equatable { case idle, working, needs2FA }
    @Published var loginStage: LoginStage = .idle
    @Published var loginStatus = ""
    private var submit2FA: ((String?) -> Void)?

    // install
    @Published var installing = false
    @Published var status = ""
    @Published var launchAtLogin = (SMAppService.mainApp.status == .enabled)
    @Published var sourceURL = ""
    @Published var sourceApps: [SourceApp] = []

    // pickers
    @Published var showAccountPicker = false
    @Published var showDevicePicker = false
    @Published var deviceOptions: [DeviceOption] = []
    private var pendingKind: InstallKind?
    private var chosenAppleID: String?

    // MARK: accounts

    func login() {
        guard !appleID.isEmpty, !password.isEmpty else { loginStatus = "Enter Apple ID and password."; return }
        ALTAppleAPI.preferSMSTwoFactorCode = textMeCode
        loginStage = .working; loginStatus = "Signing in…"
        let id = appleID, pw = password
        DispatchQueue.global().async {
            guard let anisette = Anisette.fresh() else { Task { @MainActor in self.loginStatus = "Anisette failed."; self.loginStage = .idle }; return }
            ALTAppleAPI.sharedAPI.authenticate(appleID: id, password: pw, anisetteData: anisette,
                verificationHandler: { submit in Task { @MainActor in self.submit2FA = submit; self.loginStage = .needs2FA; self.loginStatus = "Enter the 2-factor code." } },
                completionHandler: { account, session, error in
                    Task { @MainActor in
                        if let error {
                            let ns = error as NSError
                            self.loginStatus = "Sign-in failed: \(error.localizedDescription) [\(ns.code)]"; self.loginStage = .idle
                        } else if let account, let session {
                            AccountStore.add(account: account, session: session)
                            Keychain.savePassword(pw, for: account.appleID)
                            self.accounts = AccountStore.records()
                            self.appleID = ""; self.password = ""; self.code = ""; self.textMeCode = false
                            self.loginStage = .idle; self.loginStatus = ""; self.addingAccount = false
                            self.status = "Added \(account.appleID)."
                            Task.detached {
                                if let info = await Sideloader.accountTeamInfo(account: account, session: session) {
                                    await MainActor.run { AccountStore.setTeam(account.appleID, type: info.type, name: info.name); self.accounts = AccountStore.records() }
                                }
                            }
                        }
                    }
                })
        }
    }
    func submitCode() {
        guard let submit = submit2FA else { return }
        loginStage = .working; loginStatus = "Verifying…"
        let c = code.trimmingCharacters(in: .whitespaces); submit2FA = nil
        DispatchQueue.global().async { submit(c) }
    }
    func cancelLogin() { addingAccount = false; loginStage = .idle; loginStatus = ""; password = ""; code = "" }
    func removeAccount(_ id: String) { AccountStore.remove(id); accounts = AccountStore.records() }

    // MARK: source

    func loadSource() {
        let url = sourceURL; status = "Loading source…"
        Task { @MainActor in
            do { sourceApps = try await Sideloader.fetchSource(url); status = "\(sourceApps.count) app(s) available." }
            catch { status = "Couldn't load source: \(error.localizedDescription)" }
        }
    }
    func pickIPA() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true; panel.canChooseFiles = true
        var types = [UTType.application]
        if let ipa = UTType(filenameExtension: "ipa") { types.insert(ipa, at: 0) }
        panel.allowedContentTypes = types
        panel.prompt = "Install"
        if panel.runModal() == .OK, let url = panel.url { startInstall(.ipa(url.path)) }
    }
    func pickJSON() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        if let json = UTType(filenameExtension: "json") { panel.allowedContentTypes = [json] }
        panel.prompt = "Open"
        guard panel.runModal() == .OK, let u = panel.url else { return }
        do {
            let apps = try Sideloader.loadSourceFile(u.path)
            sourceApps = apps
            if apps.count == 1 { startInstall(.source(apps[0])) }
            else { status = "\(apps.count) app(s) from \(u.lastPathComponent) — pick one below." }
        } catch { status = "Couldn't read source: \(error.localizedDescription)" }
    }

    // MARK: install (resolve account → device → run)

    func startInstall(_ kind: InstallKind) {
        guard !accounts.isEmpty else { status = "Add an Apple account first."; addingAccount = true; return }
        pendingKind = kind; chosenAppleID = nil
        if accounts.count == 1 { chosenAppleID = accounts[0].appleID; resolveDevice() }
        else { showAccountPicker = true }
    }
    func chooseAccount(_ id: String) { chosenAppleID = id; showAccountPicker = false; resolveDevice() }
    private func resolveDevice() {
        status = "Looking for a connected device…"
        Task.detached {
            let devs = Sideloader.connectedDevices().map { DeviceOption(udid: $0.udid, name: $0.name) }
            await MainActor.run {
                if devs.isEmpty { self.status = "No iOS device connected. Plug in and unlock it, then try again." }
                else if devs.count == 1 { self.execute(udid: devs[0].udid) }
                else { self.deviceOptions = devs; self.showDevicePicker = true }
            }
        }
    }
    func chooseDevice(_ udid: String) { showDevicePicker = false; execute(udid: udid) }

    private func execute(udid: String) {
        guard let kind = pendingKind, let aid = chosenAppleID,
              let (account, session) = AccountStore.session(for: aid) else { status = "Couldn't load that account."; return }
        installing = true; status = "Installing…"
        Task.detached { [weak self] in
            guard let self else { return }
            let log: @Sendable (String) -> Void = { msg in print("[iSideload] \(msg)"); Task { @MainActor in self.status = String(msg.split(separator: "\n").first.map(String.init)?.prefix(160) ?? "") } }
            do {
                let result: String
                switch kind {
                case .ipa(let path): result = try await Sideloader.installFromIPA(account: account, session: session, filePath: path, iPadUDID: udid, log: log)
                case .source(let app): result = try await Sideloader.installSourceApp(account: account, session: session, app: app, iPadUDID: udid, log: log)
                }
                await MainActor.run { self.status = result }
            } catch {
                print("[iSideload] INSTALL ERROR: \(error)")
                await MainActor.run { self.status = "Failed: \(error.localizedDescription)" }
            }
            await MainActor.run { self.tracked = Tracked.all(); self.installing = false }
        }
    }

    // MARK: installed-apps management

    func loadAccountInfo() {
        for acc in accounts where acc.teamType == -1 {
            guard let (a, s) = AccountStore.session(for: acc.appleID) else { continue }
            let id = acc.appleID
            Task.detached {
                if let info = await Sideloader.accountTeamInfo(account: a, session: s) {
                    await MainActor.run { AccountStore.setTeam(id, type: info.type, name: info.name); self.accounts = AccountStore.records() }
                }
            }
        }
    }

    func expiryText(_ t: TrackedApp) -> String {
        guard let s = t.secondsUntilExpiry else { return "expiry unknown" }
        if s <= 0 { return "EXPIRED" }
        let days = Int(s / 86400)
        return days >= 1 ? "expires in \(days) day\(days == 1 ? "" : "s")" : "expires in <1 day"
    }

    func deviceIcon(_ name: String) -> String {
        let l = name.lowercased()
        if l.contains("iphone") { return "iphone" }
        if l.contains("ipod") { return "ipodtouch" }
        return "ipad"   // default (covers iPads and unknown UDIDs)
    }

    /// The account's apps grouped by app, each with the device(s) it's installed on.
    func appsGrouped(_ appleID: String) -> [(key: String, name: String, devices: [TrackedApp])] {
        let g = Dictionary(grouping: tracked.filter { $0.appleID == appleID }, by: { $0.origBundleID })
        return g.keys.sorted().map { k in
            (key: k, name: g[k]!.first!.name, devices: g[k]!.sorted { $0.udid < $1.udid })
        }
    }

    func refreshApp(_ t: TrackedApp) {
        installing = true; status = "Refreshing \(t.name) on \(t.deviceName.isEmpty ? "device" : t.deviceName)…"
        Task.detached { [weak self] in
            guard let self else { return }
            let log: @Sendable (String) -> Void = { m in print("[iSideload] \(m)"); Task { @MainActor in self.status = String(m.split(separator: "\n").first.map(String.init)?.prefix(160) ?? "") } }
            do { let r = try await Sideloader.refreshOne(t, log: log); await MainActor.run { self.status = r } }
            catch { await MainActor.run { self.status = "Refresh failed: \(error.localizedDescription)" } }
            await MainActor.run { self.tracked = Tracked.all(); self.installing = false }
        }
    }

    func removeApp(_ t: TrackedApp) {
        installing = true; status = "Removing \(t.name)…"
        Task.detached { [weak self] in
            guard let self else { return }
            let log: @Sendable (String) -> Void = { m in print("[iSideload] \(m)"); Task { @MainActor in self.status = String(m.prefix(160)) } }
            await Sideloader.removeApp(t, log: log)
            await MainActor.run { self.tracked = Tracked.all(); self.status = "Removed \(t.name)."; self.installing = false }
        }
    }

    // MARK: settings

    func setLaunchAtLogin(_ on: Bool) {
        do {
            if on { if SMAppService.mainApp.status != .enabled { try SMAppService.mainApp.register() } }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            status = "Couldn't change login item: \(error.localizedDescription)"
        }
        launchAtLogin = (SMAppService.mainApp.status == .enabled)
    }

    func refreshAllNow() {
        installing = true; status = "Refreshing all apps…"
        Task.detached { [weak self] in
            guard let self else { return }
            let log: @Sendable (String) -> Void = { m in print("[iSideload] \(m)"); Task { @MainActor in self.status = String(m.split(separator: "\n").first.map(String.init)?.prefix(160) ?? "") } }
            do { try await Sideloader.refreshAll(log: log); await MainActor.run { self.status = "Refreshed." } }
            catch { await MainActor.run { self.status = "Refresh failed: \(error.localizedDescription)" } }
            await MainActor.run { self.tracked = Tracked.all(); self.installing = false }
        }
    }
}

// ── UI ──
struct ContentView: View {
    @StateObject private var m = AppModel()
    @State private var accountsExpanded = true
    @State private var installExpanded = true
    @State private var collapsedAccounts = Set<String>()   // ids stored when COLLAPSED (default expanded)
    @State private var collapsedApps = Set<String>()

    private func accBinding(_ id: String) -> Binding<Bool> {
        Binding(get: { !collapsedAccounts.contains(id) },
                set: { collapsedAccounts = $0 ? collapsedAccounts.subtracting([id]) : collapsedAccounts.union([id]) })
    }
    private func appBinding(_ id: String) -> Binding<Bool> {
        Binding(get: { !collapsedApps.contains(id) },
                set: { collapsedApps = $0 ? collapsedApps.subtracting([id]) : collapsedApps.union([id]) })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("iSideload").font(.title2).bold()
            Text("Create free Apple accounts at [icloud.com](https://www.icloud.com/) — each free account can install **3 apps**. A $99/year Apple Developer subscription removes the limit.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

            // Accounts + their installed apps
            DisclosureGroup("Your Apple accounts", isExpanded: $accountsExpanded) {
              VStack(alignment: .leading, spacing: 8) {
            if m.accounts.isEmpty { Text("No accounts yet — add one below.").font(.caption).foregroundStyle(.secondary) }
            ForEach(m.accounts) { acc in
                let used = m.tracked.filter { $0.appleID == acc.appleID }.count
                DisclosureGroup(isExpanded: accBinding(acc.appleID)) {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(m.appsGrouped(acc.appleID), id: \.key) { grp in
                            DisclosureGroup(isExpanded: appBinding("\(acc.appleID)/\(grp.key)")) {
                                VStack(alignment: .leading, spacing: 3) {
                                    ForEach(grp.devices) { t in
                                        let devLabel = t.deviceName.isEmpty ? t.udid : t.deviceName
                                        HStack(alignment: .top, spacing: 6) {
                                            Image(systemName: m.deviceIcon(devLabel)).frame(width: 20).foregroundStyle(.secondary)
                                            VStack(alignment: .leading, spacing: 0) {
                                                Text(devLabel).font(.callout)
                                                Text(m.expiryText(t)).font(.caption2)
                                                    .foregroundStyle((t.secondsUntilExpiry ?? 1) <= 0 ? .red : .secondary)
                                            }
                                            Spacer()
                                            Button { m.refreshApp(t) } label: { Image(systemName: "arrow.clockwise") }
                                                .buttonStyle(.borderless).help("Re-sign & reinstall on this device").disabled(m.installing)
                                            Button { m.removeApp(t) } label: { Image(systemName: "minus.circle") }
                                                .buttonStyle(.borderless).help("Uninstall & free the slot").disabled(m.installing)
                                        }
                                        .padding(.leading, 42)
                                    }
                                }
                            } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: "square.grid.2x2.fill").frame(width: 20).foregroundStyle(.secondary)
                                    Text(grp.name).font(.callout)
                                }
                            }
                        }
                    }.padding(.leading, 26)
                } label: {
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: "person.crop.circle").frame(width: 20)
                        VStack(alignment: .leading, spacing: 0) {
                            Text(acc.displayName).font(.callout)
                            HStack(spacing: 6) {
                                if !acc.validity.isEmpty { Text(acc.validity).foregroundStyle(acc.isPaid ? .green : .secondary) }
                                if !acc.isPaid { Text("slots \(used)/3").foregroundStyle(used >= 3 ? .orange : .secondary) }
                            }.font(.caption2)
                        }
                        Spacer()
                        Button { m.removeAccount(acc.appleID) } label: { Image(systemName: "person.badge.minus") }
                            .buttonStyle(.borderless).help("Remove this account")
                    }
                }
            }

            if m.addingAccount || m.accounts.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    TextField("Apple ID (email)", text: $m.appleID).textFieldStyle(.roundedBorder).disabled(m.loginStage == .working)
                    SecureField("Password", text: $m.password).textFieldStyle(.roundedBorder).disabled(m.loginStage == .working).onSubmit { m.login() }
                    Toggle("Text me the code (no Apple device signed into this account)", isOn: $m.textMeCode).font(.caption).disabled(m.loginStage == .working)
                    if m.loginStage == .needs2FA {
                        HStack {
                            TextField("2-factor code", text: $m.code).textFieldStyle(.roundedBorder).frame(width: 130).onSubmit { m.submitCode() }
                            Button("Verify") { m.submitCode() }.keyboardShortcut(.defaultAction)
                        }
                    }
                    HStack {
                        Button("Sign in") { m.login() }.keyboardShortcut(.defaultAction).disabled(m.loginStage != .idle)
                        if !m.accounts.isEmpty { Button("Cancel") { m.cancelLogin() } }
                        if m.loginStage == .working { ProgressView().scaleEffect(0.6).frame(width: 14, height: 14) }
                        Text(m.loginStatus).font(.caption).foregroundStyle(.red)
                    }
                }.padding(.leading, 4)
            } else {
                Button { m.addingAccount = true } label: { Label("Add account", systemImage: "plus.circle") }.buttonStyle(.borderless)
            }
              }
            }.font(.headline)

            if !m.accounts.isEmpty {
                Divider()
                DisclosureGroup("Install", isExpanded: $installExpanded) {
                  VStack(alignment: .leading, spacing: 8) {
                HStack {
                    TextField("Source URL (AltStore repo)", text: $m.sourceURL).textFieldStyle(.roundedBorder)
                    Button("Load") { m.loadSource() }.disabled(m.installing)
                }
                ForEach(m.sourceApps) { app in
                    HStack {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(app.name).font(.callout)
                            if let v = app.version { Text("v\(v)").font(.caption2).foregroundStyle(.secondary) }
                        }
                        Spacer()
                        Button("Install") { m.startInstall(.source(app)) }.disabled(m.installing)
                    }
                }
                HStack {
                    Button("Install from .json…") { m.pickJSON() }.disabled(m.installing)
                    Button("Install from .ipa…") { m.pickIPA() }.disabled(m.installing)
                }
                  }
                }.font(.headline)
            }

            Divider()
            DisclosureGroup("Settings") {
                VStack(alignment: .leading, spacing: 6) {
                    Toggle("Launch iSideload at login (keeps apps auto-refreshed)", isOn: Binding(get: { m.launchAtLogin }, set: { m.setLaunchAtLogin($0) }))
                    Button("Refresh all apps now") { m.refreshAllNow() }.disabled(m.installing)
                    Text("iSideload keeps apps signed while it runs in the menu bar — it re-signs automatically when you plug in a device and every couple of hours. No separate background program is needed.")
                        .font(.caption2).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }.padding(.top, 2)
            }.font(.callout)

            HStack {
                if m.installing { ProgressView().scaleEffect(0.6).frame(width: 16, height: 16) }
                Text(m.status).font(.callout).foregroundStyle(m.status.hasPrefix("✅") ? .green : (m.status.hasPrefix("Failed") ? .red : .primary))
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Quit iSideload") { NSApplication.shared.terminate(nil) }.controlSize(.small).buttonStyle(.borderless)
            }
        }
        .padding(20)
        .frame(width: 440)
        .focusEffectDisabled()   // no stray blue keyboard-focus ring when the popover opens
        .onAppear { m.loadAccountInfo() }
        .confirmationDialog("Which Apple account?", isPresented: $m.showAccountPicker, titleVisibility: .visible) {
            ForEach(m.accounts) { acc in Button(acc.displayName) { m.chooseAccount(acc.appleID) } }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog("Which device?", isPresented: $m.showDevicePicker, titleVisibility: .visible) {
            ForEach(m.deviceOptions) { d in Button(d.name) { m.chooseDevice(d.udid) } }
            Button("Cancel", role: .cancel) {}
        }
    }
}

@main
struct InstallerApp: App {
    init() {
        installDiagnosticsLog()
        RefreshDaemon.shared.start()
        // Launch at login is ON by default — register once on first run; the Settings
        // toggle can turn it off afterwards (we don't re-enable once configured).
        if !UserDefaults.standard.bool(forKey: "isideload.loginItemConfigured") {
            try? SMAppService.mainApp.register()
            UserDefaults.standard.set(true, forKey: "isideload.loginItemConfigured")
        }
    }
    var body: some Scene {
        MenuBarExtra("iSideload", systemImage: "shippingbox") {
            RootPanel()
        }
        .menuBarExtraStyle(.window)
    }
}

// Measures the intrinsic height of the content and sizes the window to fit it, so
// the panel grows/shrinks as sections expand or collapse. A ScrollView only kicks
// in (showing its bar) when the content would be taller than the screen.
private struct ContentHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
}

struct RootPanel: View {
    // Start with a sensible height so the window is never 0-tall before the first
    // measurement lands (a 0 frame makes the popover open empty/invisible).
    @State private var contentHeight: CGFloat = 560
    private var maxHeight: CGFloat { (NSScreen.main?.visibleFrame.height ?? 900) - 48 }
    var body: some View {
        ScrollView {
            ContentView()
                .background(GeometryReader { g in
                    Color.clear.preference(key: ContentHeightKey.self, value: g.size.height)
                })
        }
        .frame(width: 470, height: min(max(contentHeight, 120), maxHeight))
        .onPreferenceChange(ContentHeightKey.self) { h in
            if h > 1 { contentHeight = h }
        }
        .background(Color.white)
        .environment(\.colorScheme, .light)   // pure-white page, readable in dark mode too
    }
}
