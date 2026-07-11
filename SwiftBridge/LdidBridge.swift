//
//  LdidBridge.swift
//  AltSign
//
//  Created by Magesh K on 07/07/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import NativeBridge
import OpenSSL

// MARK: - Certificate Chain Constants

private let AppleRootCertificateData = """
-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
"""

private let AppleWWDRCertificateData = """
-----BEGIN CERTIFICATE-----
MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi
MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw
bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg
Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB
cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ
BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ
C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW
BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj
+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b
5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A
0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS
VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j
BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG
AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh
MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js
MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw
EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH
Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA
HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK
XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7
bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC
NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza
UDSdlTs=
-----END CERTIFICATE-----
"""

private let LegacyAppleWWDRCertificateData = """
-----BEGIN CERTIFICATE-----
MIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp
ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTEz
MDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVTMRMwEQYD
VQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3Bl
ciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0U3rOfGOA
YXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkVCBmsqtsq
Mu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8V25nNYB2
NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHld0WNUEi6
Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1qarunFjVg
0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGjgaYwgaMw
HQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQFMAMBAf8w
HwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcwJTAjoCGg
H4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/BAQDAgGG
MBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Zviz1smwv
j+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/Nw0Uwj6OD
Dc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJTleMa1s8
Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1VAKmuu0sw
ruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur+cmV6U/k
TecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxRpVzscYqC
tGwPDBUf
-----END CERTIFICATE-----
"""

// MARK: - Closure wrapper for context pointers

private class ClosureBox<T> {
    let closure: T
    init(_ closure: T) {
        self.closure = closure
    }
}

// MARK: - C trampolines

private let ldid_entitlement_trampoline: @convention(c) (UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> UnsafePointer<CChar>? = { cPath, context in
    guard let cPath, let context else { return nil }
    let box = Unmanaged<ClosureBox<(String) -> String>>.fromOpaque(context).takeUnretainedValue()
    let value = box.closure(String(cString: cPath))
    return strdup(value).map { UnsafePointer($0) }
}

private let ldid_progress_trampoline: @convention(c) (UnsafeMutableRawPointer?) -> Void = { context in
    guard let context else { return }
    let box = Unmanaged<ClosureBox<() -> Void>>.fromOpaque(context).takeUnretainedValue()
    box.closure()
}

private let free_x509_callback: @convention(c) (UnsafeMutableRawPointer?) -> Void = { ptr in
    if let ptr = ptr {
        X509_free(OpaquePointer(ptr))
    }
}

// MARK: - Public Bridge

public enum LdidBridge {

    public enum Error: Swift.Error {
        case invalidPath
        case operationFailed(String)
    }

    // MARK: Read APIs

    private static func findExecutable(at url: URL) -> URL? {
        let plistURL = url.appendingPathComponent("Info.plist")
        guard let plistData = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any],
              let executableName = plist["CFBundleExecutable"] as? String
        else {
            // Check Contents/Info.plist (macOS App Bundle structure)
            let contentsPlistURL = url.appendingPathComponent("Contents/Info.plist")
            if let contentsData = try? Data(contentsOf: contentsPlistURL),
               let contentsPlist = try? PropertyListSerialization.propertyList(from: contentsData, options: [], format: nil) as? [String: Any],
               let contentsExecName = contentsPlist["CFBundleExecutable"] as? String {
                let path = url.appendingPathComponent("Contents/MacOS/\(contentsExecName)")
                if FileManager.default.fileExists(atPath: path.path) {
                    return path
                }
            }
            return nil
        }
        
        let path = url.appendingPathComponent(executableName)
        if FileManager.default.fileExists(atPath: path.path) {
            return path
        }
        
        let macPath = url.appendingPathComponent("Contents/MacOS/\(executableName)")
        if FileManager.default.fileExists(atPath: macPath.path) {
            return macPath
        }
        
        let macResourcesPath = url.appendingPathComponent("Resources/\(executableName)")
        if FileManager.default.fileExists(atPath: macResourcesPath.path) {
            return macResourcesPath
        }
        
        return nil
    }

    public static func entitlements(at url: URL) throws -> String {
        verboseLog("[AltSign] LdidBridge.entitlements(at: \(url.path)) started")
        
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else {
            throw Error.invalidPath
        }
        
        let targetURL: URL
        if isDir.boolValue {
            guard let execURL = findExecutable(at: url) else {
                throw Error.operationFailed("Failed to locate executable in bundle: \(url.path)")
            }
            targetURL = execURL
        } else {
            targetURL = url
        }
        
        do {
            let parser = try MachOParser(url: targetURL)
            let result = try parser.entitlements()
            verboseLog("[AltSign] LdidBridge.entitlements parsed successfully. Length: \(result.count) chars")
            verboseLog("[AltSign] LdidBridge.entitlements: \(result)")
            return result
        } catch MachOParserError.missingSignature {
            verboseLog("[AltSign] LdidBridge.entitlements parsed successfully: unsigned/no entitlements. Returning empty string.")
            return ""
        } catch {
            debugLog("[AltSign] LdidBridge.entitlements failed to parse Mach-O: \(error)")
            throw Error.operationFailed("Failed to parse Mach-O entitlements: \(error.localizedDescription)")
        }
    }

    public static func requirements(at url: URL) throws -> String {
        verboseLog("[AltSign] LdidBridge.requirements(at: \(url.path)) started")
        
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else {
            throw Error.invalidPath
        }
        
        let targetURL: URL
        if isDir.boolValue {
            guard let execURL = findExecutable(at: url) else {
                throw Error.operationFailed("Failed to locate executable in bundle: \(url.path)")
            }
            targetURL = execURL
        } else {
            targetURL = url
        }
        
        do {
            let parser = try MachOParser(url: targetURL)
            let result = try parser.requirements()
            verboseLog("[AltSign] LdidBridge.requirements parsed successfully. Length: \(result.count) chars")
            return result
        } catch MachOParserError.missingSignature {
            verboseLog("[AltSign] LdidBridge.requirements parsed successfully: unsigned/no requirements. Returning empty string.")
            return ""
        } catch {
            debugLog("[AltSign] LdidBridge.requirements failed to parse Mach-O: \(error)")
            throw Error.operationFailed("Failed to parse Mach-O requirements: \(error.localizedDescription)")
        }
    }

    // MARK: - Certificate Chain Builder (Pure Swift)

    private static func buildCertificateChain(p12Data: Data) throws -> Data {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }
        
        _ = p12Data.withUnsafeBytes { buf in
            BIO_write(bio, buf.baseAddress, Int32(p12Data.count))
        }
        
        guard let inputP12 = d2i_PKCS12_bio(bio, nil) else {
            throw Error.operationFailed("failed to parse PKCS12 data")
        }
        defer { PKCS12_free(inputP12) }
        
        var key: OpaquePointer? = nil
        var cert: OpaquePointer? = nil
        
        guard PKCS12_parse(inputP12, "", &key, &cert, nil) == 1 else {
            throw Error.operationFailed("failed to decrypt PKCS12 data")
        }
        defer {
            if let key { EVP_PKEY_free(key) }
            if let cert { X509_free(cert) }
        }
        
        guard let key, let cert else {
            throw Error.operationFailed("key or certificate missing")
        }
        
        guard let certificates = OPENSSL_sk_new_null() else {
            throw Error.operationFailed("allocation failed")
        }
        defer { OPENSSL_sk_pop_free(certificates, free_x509_callback) }
        
        let readCertFromPEM: (String) -> OpaquePointer? = { pemStr in
            guard let data = pemStr.data(using: .utf8) else { return nil }
            return CertificatesManager.readCert(data)
        }
        


        guard let rootCert = readCertFromPEM(AppleRootCertificateData) else {
            let openSSLErr = getOpenSSLError()
            throw Error.operationFailed("failed to parse Apple Root CA certificate during chain of trust packaging\ncause: \(openSSLErr)")
        }
        OPENSSL_sk_push(certificates, UnsafeRawPointer(rootCert))
        
        let issuerHash = X509_issuer_name_hash(cert)
        let wwdrData = (issuerHash == 0x817d2f7a)
            ? LegacyAppleWWDRCertificateData
            : AppleWWDRCertificateData
            
        guard let wwdrCert = readCertFromPEM(wwdrData) else {
            let openSSLErr = getOpenSSLError()
            throw Error.operationFailed("failed to parse Apple WWDR certificate during chain of trust packaging\ncause: \(openSSLErr)")
        }
        OPENSSL_sk_push(certificates, UnsafeRawPointer(wwdrCert))
        
        guard let outputP12 = PKCS12_create("", "", key, cert, certificates, 0, 0, 0, 0, 0) else {
            let openSSLErr = getOpenSSLError()
            throw Error.operationFailed("failed to package certificate chain during chain of trust packaging\ncause: \(openSSLErr)")
        }
        defer { PKCS12_free(outputP12) }
        
        let outputBio = BIO_new(BIO_s_mem())
        defer { BIO_free(outputBio) }
        
        i2d_PKCS12_bio(outputBio, outputP12)
        
        guard let outputData = CertificatesManager.dataFromBIO(outputBio) else {
            let openSSLErr = getOpenSSLError()
            throw Error.operationFailed("failed to retrieve packaged chain data during chain of trust packaging\ncause: \(openSSLErr)")
        }
        
        return outputData
    }

    // MARK: - Signing API

    public static func sign(
        appPath: String,
        keyData: Data,
        entitlementProvider: @escaping (String) -> String,
        progress: @escaping () -> Void
    ) throws {
        verboseLog("[AltSign] LdidBridge.sign started for appPath: \(appPath), keyData: \(keyData.count) bytes")

        guard !appPath.isEmpty else {
            debugLog("[AltSign] LdidBridge.sign failed: appPath is empty")
            throw Error.invalidPath
        }

        let chainData = try buildCertificateChain(p12Data: keyData)

        var targetPath = appPath
        if !targetPath.hasSuffix("/") {
            targetPath += "/"
        }

        // Wrap closures in boxes to pass them as context pointers
        let entitlementBox = ClosureBox(entitlementProvider)
        let progressBox = ClosureBox(progress)

        let entitlementCtx = Unmanaged.passUnretained(entitlementBox).toOpaque()
        let progressCtx = Unmanaged.passUnretained(progressBox).toOpaque()

        var errorPtr: UnsafeMutablePointer<CChar>? = nil

        let status = chainData.withUnsafeBytes { buf in
            native_bridge_ldid_sign(
                targetPath,
                buf.bindMemory(to: UInt8.self).baseAddress,
                Int32(chainData.count),
                ldid_entitlement_trampoline,
                entitlementCtx,
                ldid_progress_trampoline,
                progressCtx,
                &errorPtr
            )
        }

        if status != 0 {
            let message = errorPtr.map { String(cString: $0) } ?? "ldid sign failed"
            debugLog("[AltSign] LdidBridge.sign native signing failed with error: \(message)")
            if let errorPtr { native_bridge_free_string(errorPtr) }
            throw Error.operationFailed(message)
        }

        verboseLog("[AltSign] LdidBridge.sign native signing completed successfully")
    }
}
