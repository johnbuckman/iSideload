//
//  CertificatesManager.swift
//  AltSign
//
//  Created by Magesh K on 07/07/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import OpenSSL

public enum CertificatesManager {

    public struct CSRSubject {
        public let country: String
        public let state: String
        public let locality: String
        public let organization: String
        public let commonName: String

        public init(
            country: String,
            state: String,
            locality: String,
            organization: String,
            commonName: String
        ) {
            self.country = country
            self.state = state
            self.locality = locality
            self.organization = organization
            self.commonName = commonName
        }
    }

    public enum Error: Swift.Error {
        case operationFailed(String)
    }

    private static func readBIO<T>(_ data: Data, reader: (OpaquePointer?) -> T?) -> T? {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }
        _ = data.withUnsafeBytes { buf in
            BIO_write(bio, buf.baseAddress, Int32(data.count))
        }
        return reader(bio)
    }

    private static func parse<T>(
        _ data: Data,
        boundaryKeyword: String,
        pemReader: (OpaquePointer?) -> T?,
        derReader: (OpaquePointer?) -> T?
    ) -> T? {
        // Try raw PEM format first
        if let parsed = readBIO(data, reader: pemReader) {
            return parsed
        }

        guard let text = String(data: data, encoding: .utf8) else {
            return nil
        }

        let lines = text.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)

        guard let beginIndex = lines.firstIndex(where: { $0.contains("-----BEGIN ") && $0.contains("\(boundaryKeyword)-----") }),
              let endIndex = lines[beginIndex...].firstIndex(where: { $0.contains("-----END ") && $0.contains("\(boundaryKeyword)-----") }) else {
            return nil
        }

        let blockLines = Array(lines[beginIndex...endIndex])
        let normalizedPEM = blockLines.joined(separator: "\n")

        if let parsed = readBIO(Data(normalizedPEM.utf8), reader: pemReader) {
            return parsed
        }

        // Fallback to DER and see if readable
        let base64Body = lines[(beginIndex + 1)..<endIndex]
            .filter { !$0.hasPrefix("Bag Attributes") }
            .filter { !$0.hasPrefix("    ") }
            .filter { !$0.hasPrefix("localKeyID:") }
            .filter { !$0.hasPrefix("friendlyName:") }
            .filter { !$0.hasPrefix("Key Attributes:") }
            .joined()

        guard let derData = Data(base64Encoded: base64Body, options: .ignoreUnknownCharacters) else {
            return nil
        }

        return readBIO(derData, reader: derReader)
    }

    static func readCert(_ data: Data) -> OpaquePointer? {
        // Try DER first
        if let cert = readBIO(data, reader: { d2i_X509_bio($0, nil) }) {
            return cert
        }
        
        // Fallback to PEM
        return parse(data, boundaryKeyword: "CERTIFICATE",
            pemReader: { PEM_read_bio_X509($0, nil, nil, nil) },
            derReader: { d2i_X509_bio($0, nil) }
        )
    }

    static func readPrivateKey(_ data: Data) -> OpaquePointer? {
        // Try DER first
        if let key = readBIO(data, reader: { d2i_PrivateKey_bio($0, nil) }) {
            return key
        }
        
        // Fallback to PEM
        return parse(data, boundaryKeyword: "PRIVATE KEY",
            pemReader: { PEM_read_bio_PrivateKey($0, nil, nil, nil) },
            derReader: { d2i_PrivateKey_bio($0, nil) }
        )
    }

    static func dataFromBIO(_ bio: OpaquePointer?) -> Data? {
        guard let bio = bio else { return nil }
        var ptr: UnsafeMutablePointer<CChar>? = nil
        let len = Int(BIO_ctrl(bio, 3, 0, &ptr)) // BIO_CTRL_INFO = 3
        guard len > 0, let rawPtr = ptr else { return nil }
        return Data(bytes: rawPtr, count: len)
    }



    // MARK: - Public API

    public static func generateCSR(
        subject: CSRSubject
    ) throws -> (csr: Data, privateKey: Data) {

        verboseLog("""
        [AltSign] CertificatesManager.generateCSR started:
          • Country: \(subject.country)
          • State: \(subject.state)
          • Locality: \(subject.locality)
          • Organization: \(subject.organization)
          • Common Name: \(subject.commonName)
        """)

        guard let bignum = BN_new(),
              let rsa = RSA_new(),
              let pkey = EVP_PKEY_new(),
              let req = X509_REQ_new() else {
            throw Error.operationFailed("Allocation failed")
        }

        var rsaFreed = false
        defer {
            BN_free(bignum)
            if !rsaFreed { RSA_free(rsa) }
            EVP_PKEY_free(pkey)
            X509_REQ_free(req)
        }

        guard BN_set_word(bignum, 65537) == 1 else {
            throw Error.operationFailed("BN_set_word failed")
        }

        guard RSA_generate_key_ex(rsa, 2048, bignum, nil) == 1 else {
            throw Error.operationFailed("RSA_generate_key_ex failed")
        }

        guard EVP_PKEY_set1_RSA(pkey, rsa) == 1 else {
            throw Error.operationFailed("EVP_PKEY_set1_RSA failed")
        }
        rsaFreed = true

        guard X509_REQ_set_version(req, 0) == 1 else {
            throw Error.operationFailed("set_version failed")
        }

        guard let name = X509_REQ_get_subject_name(req) else {
            throw Error.operationFailed("subject build failed")
        }

        let addEntry: (String, String) -> Bool = { field, value in
            return X509_NAME_add_entry_by_txt(name, field, 0x1001, value, -1, -1, 0) == 1 // MBSTRING_ASC = 0x1001
        }

        guard addEntry("C", subject.country),
              addEntry("ST", subject.state),
              addEntry("L", subject.locality),
              addEntry("O", subject.organization),
              addEntry("CN", subject.commonName) else {
            throw Error.operationFailed("subject build failed")
        }

        guard X509_REQ_set_pubkey(req, pkey) == 1 else {
            throw Error.operationFailed("set_pubkey failed")
        }

        guard X509_REQ_sign(req, pkey, EVP_sha1()) > 0 else {
            throw Error.operationFailed("sign failed")
        }

        let csrBIO = BIO_new(BIO_s_mem())
        let keyBIO = BIO_new(BIO_s_mem())
        defer {
            BIO_free(csrBIO)
            BIO_free(keyBIO)
        }

        guard PEM_write_bio_X509_REQ(csrBIO, req) == 1,
              PEM_write_bio_PrivateKey(keyBIO, pkey, nil, nil, 0, nil, nil) == 1 else {
            throw Error.operationFailed("PEM write failed")
        }

        guard let csrData = dataFromBIO(csrBIO),
              let keyData = dataFromBIO(keyBIO) else {
            throw Error.operationFailed("BIO allocation failed")
        }

        verboseLog("[AltSign] CertificatesManager.generateCSR succeeded. Generated CSR size: \(csrData.count) bytes, privateKey size: \(keyData.count) bytes")
        return (csrData, keyData)
    }

    public static func extractPKCS12(
        _ data: Data,
        password: String?
    ) throws -> (cert: Data, key: Data) {

        verboseLog("[AltSign] CertificatesManager.extractPKCS12 started. Data size: \(data.count) bytes, hasPassword: \(password != nil)")

        guard let p12 = readBIO(data, reader: { d2i_PKCS12_bio($0, nil) }) else {
            throw ALTCertificateError.invalidFormat(cause: getOpenSSLError())
        }
        defer { PKCS12_free(p12) }

        var key: OpaquePointer? = nil
        var cert: OpaquePointer? = nil
        var parsed = false
        let passwordList = [password, "", nil]

        for pass in passwordList {
            let passStr = pass?.cString(using: .utf8)
            var keyPtr: OpaquePointer? = nil
            var certPtr: OpaquePointer? = nil

            let res = passStr?.withUnsafeBufferPointer { buf in
                PKCS12_parse(p12, buf.baseAddress, &keyPtr, &certPtr, nil)
            } ?? PKCS12_parse(p12, nil, &keyPtr, &certPtr, nil)

            if res == 1 {
                key = keyPtr
                cert = certPtr
                parsed = true
                break
            } else {
                if let keyPtr { EVP_PKEY_free(keyPtr) }
                if let certPtr { X509_free(certPtr) }
            }
        }

        guard parsed, let cert, let key else {
            throw ALTCertificateError.decryptionFailed(cause: getOpenSSLError())
        }
        defer {
            EVP_PKEY_free(key)
            X509_free(cert)
        }

        let certBIO = BIO_new(BIO_s_mem())
        let keyBIO = BIO_new(BIO_s_mem())
        defer {
            BIO_free(certBIO)
            BIO_free(keyBIO)
        }

        PEM_write_bio_X509(certBIO, cert)
        PEM_write_bio_PrivateKey(keyBIO, key, nil, nil, 0, nil, nil)

        guard let certData = dataFromBIO(certBIO),
              let keyData = dataFromBIO(keyBIO) else {
            throw ALTCertificateError.memoryAllocationFailed(cause: getOpenSSLError())
        }

        verboseLog("[AltSign] CertificatesManager.extractPKCS12 succeeded. Extracted cert size: \(certData.count) bytes, key size: \(keyData.count) bytes")
        return (certData, keyData)
    }

    public static func parseCertificate(
        _ data: Data
    ) -> (name: String, serial: String)? {

        verboseLog("[AltSign] CertificatesManager.parseCertificate started. Cert size: \(data.count) bytes")

        guard let cert = readCert(data) else {
            verboseLog("[AltSign] CertificatesManager.parseCertificate failed: readCert returned null")
            return nil
        }
        defer { X509_free(cert) }

        guard let subject = X509_get_subject_name(cert) else { return nil }

        let idx = X509_NAME_get_index_by_NID(subject, 13, -1) // NID_commonName = 13
        guard idx != -1 else { return nil }

        guard let entry = X509_NAME_get_entry(subject, idx) else { return nil }
        guard let nameData = X509_NAME_ENTRY_get_data(entry) else { return nil }

        guard let cname = ASN1_STRING_get0_data(nameData) else { return nil }
        let name = String(cString: cname)

        guard let serialASN = X509_get_serialNumber(cert) else { return nil }
        guard let bn = ASN1_INTEGER_to_BN(serialASN, nil) else { return nil }
        defer { BN_free(bn) }

        guard let hexPtr = BN_bn2hex(bn) else { return nil }
        defer { CRYPTO_free(hexPtr, nil, 0) }

        let serial = String(cString: hexPtr)
        verboseLog("[AltSign] CertificatesManager.parseCertificate succeeded. Name: \(name), Serial: \(serial)")
        return (name, serial)
    }

    public static func createPKCS12(
        cert: Data,
        key: Data?,
        password: String
    ) throws -> Data {

        verboseLog("[AltSign] CertificatesManager.createPKCS12 started. Cert size: \(cert.count) bytes, hasKey: \(key != nil)")

        guard let certX509 = readCert(cert) else {
            let firstBytes = cert.prefix(4).map { String(format: "%02x", $0) }.joined()
            let cause = getOpenSSLError()
            debugLog("[AltSign] CertificatesManager.createPKCS12 failed: readCert returned nil (cert data size: \(cert.count) bytes, first bytes: \(firstBytes)) (cause: \(cause))")
            throw Error.operationFailed("failed to parse certificate during PKCS12 generation\ncause: \(cause)")
        }
        defer { X509_free(certX509) }

        var keyPkey: OpaquePointer? = nil
        if let keyData = key {
            keyPkey = readPrivateKey(keyData)
            if keyPkey == nil {
                let cause = getOpenSSLError()
                debugLog("[AltSign] CertificatesManager.createPKCS12 failed: readPrivateKey returned nil (key data size: \(keyData.count) bytes) (cause: \(cause))")
                throw Error.operationFailed("failed to parse private key during PKCS12 generation\ncause: \(cause)")
            }
        }
        defer { if let keyPkey { EVP_PKEY_free(keyPkey) } }

        guard let p12 = PKCS12_create(password, "", keyPkey, certX509, nil, 0, 0, 0, 0, 0) else {
            let cause = getOpenSSLError()
            debugLog("[AltSign] CertificatesManager.createPKCS12 failed: PKCS12_create returned nil (cause: \(cause))")
            throw Error.operationFailed("failed to create PKCS12 container\ncause: \(cause)")
        }
        defer { PKCS12_free(p12) }

        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        i2d_PKCS12_bio(bio, p12)

        guard let result = dataFromBIO(bio) else {
            let cause = getOpenSSLError()
            debugLog("[AltSign] CertificatesManager.createPKCS12 failed: dataFromBIO returned nil (cause: \(cause))")
            throw Error.operationFailed("failed to read PKCS12 data from BIO\ncause: \(cause)")
        }

        verboseLog("[AltSign] CertificatesManager.createPKCS12 succeeded. Output size: \(result.count) bytes")
        return result
    }
}

public func getOpenSSLError() -> String {
    let errCode = ERR_get_error()
    guard errCode != 0 else { return "unknown error" }
    var buf = [CChar](repeating: 0, count: 256)
    ERR_error_string_n(errCode, &buf, buf.count)
    return String(cString: buf)
}
