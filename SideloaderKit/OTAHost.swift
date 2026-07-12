import Foundation
import Network
import Security

/// Serves an already-ad-hoc-signed `.ipa` for over-the-air (`itms-services`) install over
/// a trusted HTTPS URL, so a device can install it by scanning a QR code — no cable, no
/// inbound connection to the device. Uses the free **local-ip.co** service: it maps
/// `<dashed-lan-ip>.my.local-ip.co` → the Mac's LAN IP for anyone, and publishes a
/// publicly-trusted GlobalSign wildcard cert for `*.my.local-ip.co` that iOS accepts.
///
/// The IPA must already be ad-hoc/enterprise signed (`IPAInfo.otaCapable`); we don't
/// re-sign — we just host it. Verify end-to-end on a device (the TLS path can't be
/// exercised without one).
public final class OTAHost: @unchecked Sendable {
    public static let shared = OTAHost()
    private var listener: NWListener?
    private var serveDir: String = ""
    private var ipaName = "app.ipa"
    public private(set) var portalURL: URL?
    private let port: UInt16 = 8443

    /// Stage <ipa> + manifest + a one-tap install page, start the HTTPS server, and return
    /// the portal URL to encode in a QR. Throws if the LAN IP or cert can't be obtained.
    public func start(ipaPath: String, info: IPAInfo) throws -> URL {
        stop()
        guard let ip = Self.lanIPv4() else { throw err("Couldn't determine this Mac's Wi-Fi IP address.") }
        let host = ip.replacingOccurrences(of: ".", with: "-") + ".my.local-ip.co"

        // staging dir
        let dir = NSTemporaryDirectory() + "isideload-ota-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        serveDir = dir
        ipaName = (safe(info.appName).isEmpty ? "app" : safe(info.appName)) + ".ipa"
        try FileManager.default.copyItem(atPath: ipaPath, toPath: dir + "/" + ipaName)

        let base = "https://\(host):\(port)"
        try manifest(info: info, ipaURL: "\(base)/\(ipaName)").write(toFile: dir + "/manifest.plist", atomically: true, encoding: .utf8)
        try page(info: info, manifestURL: "\(base)/manifest.plist").write(toFile: dir + "/index.html", atomically: true, encoding: .utf8)

        // TLS identity from the local-ip.co cert, then listen
        let identity = try Self.localIPIdentity()
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, identity)
        let params = NWParameters(tls: tls)
        params.allowLocalEndpointReuse = true
        let l = try NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!)
        l.newConnectionHandler = { [weak self] c in self?.handle(c) }
        l.start(queue: .global())
        listener = l

        let url = URL(string: "\(base)/")!
        portalURL = url
        return url
    }

    public func stop() {
        listener?.cancel(); listener = nil; portalURL = nil
        if !serveDir.isEmpty { try? FileManager.default.removeItem(atPath: serveDir); serveDir = "" }
    }

    // MARK: HTTP (minimal)

    private func handle(_ conn: NWConnection) {
        conn.start(queue: .global())
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, _ in
            guard let self, let data, let reqLine = String(data: data, encoding: .utf8)?.split(separator: "\r\n").first else { conn.cancel(); return }
            let parts = reqLine.split(separator: " ")
            let rawPath = parts.count >= 2 ? String(parts[1]) : "/"
            let path = rawPath == "/" ? "/index.html" : String(rawPath.split(separator: "?").first ?? "")
            self.serve(path, on: conn)
        }
    }

    private func serve(_ path: String, on conn: NWConnection) {
        let file = serveDir + path
        guard FileManager.default.fileExists(atPath: file), let body = FileManager.default.contents(atPath: file) else {
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            conn.send(content: resp.data(using: .utf8), completion: .contentProcessed { _ in conn.cancel() }); return
        }
        let ctype = path.hasSuffix(".ipa") ? "application/octet-stream"
                  : path.hasSuffix(".plist") ? "application/xml" : "text/html; charset=utf-8"
        var header = "HTTP/1.1 200 OK\r\nContent-Type: \(ctype)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".data(using: .utf8)!
        header.append(body)
        conn.send(content: header, completion: .contentProcessed { _ in conn.cancel() })
    }

    // MARK: content

    private func manifest(info: IPAInfo, ipaURL: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>items</key><array><dict>
          <key>assets</key><array><dict>
            <key>kind</key><string>software-package</string>
            <key>url</key><string>\(ipaURL)</string>
          </dict></array>
          <key>metadata</key><dict>
            <key>bundle-identifier</key><string>\(info.bundleID)</string>
            <key>bundle-version</key><string>\(info.version.isEmpty ? "1.0" : info.version)</string>
            <key>kind</key><string>software</string>
            <key>title</key><string>\(xml(info.appName))</string>
          </dict>
        </dict></array></dict></plist>
        """
    }

    private func page(info: IPAInfo, manifestURL: String) -> String {
        let link = "itms-services://?action=download-manifest&amp;url=\(manifestURL)"
        return """
        <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head>
        <body style="font-family:-apple-system;background:#16232f;color:#fff;text-align:center;padding:48px 24px">
        <h1 style="font-size:28px">\(xml(info.appName))</h1>
        <p style="color:#9fb0be">Tap to install over the air — nothing else to do to your device.</p>
        <p><a style="display:inline-block;margin-top:14px;padding:18px 30px;background:#22c1b6;color:#08202a;font-weight:700;border-radius:14px;text-decoration:none" href="\(link)">Install \(xml(info.appName))</a></p>
        </body></html>
        """
    }

    // MARK: helpers

    /// Build a `sec_identity_t` from the local-ip.co leaf cert+key plus the correct
    /// GlobalSign intermediate (fetched via the leaf's AIA), so iOS gets a full trusted chain.
    private static func localIPIdentity() throws -> sec_identity_t {
        let tmp = NSTemporaryDirectory() + "isideload-cert-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        func fetch(_ url: String, _ name: String) throws {
            guard let u = URL(string: url), let d = try? Data(contentsOf: u), !d.isEmpty else { throw err("Couldn't fetch \(name).") }
            try d.write(to: URL(fileURLWithPath: tmp + "/" + name))
        }
        try fetch("https://local-ip.co/cert/server.pem", "server.pem")
        try fetch("https://local-ip.co/cert/server.key", "server.key")
        // the correct GlobalSign intermediate (local-ip.co's own chain.pem is stale/mismatched)
        try fetch("http://secure.globalsign.com/cacert/gsgccr6alphasslca2025.crt", "inter.der")
        _ = run("/usr/bin/openssl", ["x509", "-inform", "der", "-in", tmp + "/inter.der", "-out", tmp + "/inter.pem"])
        // bundle leaf+key(+intermediate) into a PKCS12 to import as a SecIdentity
        _ = run("/usr/bin/openssl", ["pkcs12", "-export", "-inkey", tmp + "/server.key",
                "-in", tmp + "/server.pem", "-certfile", tmp + "/inter.pem",
                "-passout", "pass:isideload", "-out", tmp + "/id.p12"])
        guard let p12 = FileManager.default.contents(atPath: tmp + "/id.p12") else { throw err("Couldn't build TLS identity.") }
        var items: CFArray?
        let status = SecPKCS12Import(p12 as CFData, [kSecImportExportPassphrase as String: "isideload"] as CFDictionary, &items)
        guard status == errSecSuccess,
              let arr = items as? [[String: Any]], let first = arr.first,
              let idAny = first[kSecImportItemIdentity as String] else { throw err("TLS identity import failed (\(status)).") }
        let secIdentity = idAny as! SecIdentity
        // Present the full chain (leaf + GlobalSign intermediate) so iOS can validate;
        // sec_identity_create() alone sends only the leaf.
        if let interDER = FileManager.default.contents(atPath: tmp + "/inter.der"),
           let interCert = SecCertificateCreateWithData(nil, interDER as CFData),
           let sid = sec_identity_create_with_certificates(secIdentity, [interCert] as CFArray) {
            return sid
        }
        guard let sid = sec_identity_create(secIdentity) else { throw err("Couldn't create TLS identity.") }
        return sid
    }

    /// The Mac's IPv4 address on the primary Wi-Fi/Ethernet interface (en0/en1).
    static func lanIPv4() -> String? {
        var ptr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ptr) == 0, let first = ptr else { return nil }
        defer { freeifaddrs(ptr) }
        var best: String?
        var a: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = a {
            let ifa = cur.pointee
            if ifa.ifa_addr.pointee.sa_family == UInt8(AF_INET) {
                let name = String(cString: ifa.ifa_name)
                if name == "en0" || name == "en1" {
                    var hn = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(ifa.ifa_addr, socklen_t(ifa.ifa_addr.pointee.sa_len), &hn, socklen_t(hn.count), nil, 0, NI_NUMERICHOST) == 0 {
                        let ip = String(cString: hn)
                        if ip.hasPrefix("169.254.") == false { if name == "en0" { return ip }; best = best ?? ip }
                    }
                }
            }
            a = ifa.ifa_next
        }
        return best
    }

    private func safe(_ s: String) -> String { s.components(separatedBy: CharacterSet.alphanumerics.inverted).joined() }
    private func xml(_ s: String) -> String { s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;") }
}

private func err(_ m: String) -> NSError { NSError(domain: "iSideload.OTAHost", code: 1, userInfo: [NSLocalizedDescriptionKey: m]) }
@discardableResult private func run(_ tool: String, _ args: [String]) -> Int32 {
    let p = Process(); p.executableURL = URL(fileURLWithPath: tool); p.arguments = args
    p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
    try? p.run(); p.waitUntilExit(); return p.terminationStatus
}
