//
//  GSAContext.swift
//  AltSign
//
//  Created by Riley Testut on 8/15/20.
//  Copyright © 2020 Riley Testut. All rights reserved.
//

import Foundation
import SwiftBridge

class GSAContext {

    let username: String
    let password: String

    /// salt (obtained from server in SRP challenge)
    var salt: Data?

    /// B — server public key (obtained from server in SRP challenge)
    var serverPublicKey: Data?

    /// K — shared session key, established after a successful SRP handshake
    var sessionKey: Data?

    var dsid: String?

    /// A — client public key generated at the start of the SRP handshake
    private(set) var publicKey: Data?

    /// x — password-derived key computed from password + salt via PBKDF2
    private(set) var derivedPasswordKey: Data?

    /// M1 — client proof message sent to server to prove knowledge of password
    private(set) var verificationMessage: Data?

    private lazy var srp = CoreCryptoBridge.SRP()

    init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}

extension GSAContext {

    func start() -> Data? {
        guard self.publicKey == nil else { return nil }

        verboseLog("[AltSign] GSAContext.start: generating client public key A")
        self.publicKey = self.makeAKey()
        if let key = self.publicKey {
            verboseLog("[AltSign] GSAContext.start succeeded. Public key length: \(key.count) bytes")
        } else {
            verboseLog("[AltSign] GSAContext.start failed: makeAKey returned nil")
        }
        return self.publicKey
    }

    func makeVerificationMessage(iterations: Int, isHexadecimal: Bool) -> Data? {
        guard self.verificationMessage == nil else { return nil }

        guard let salt = self.salt,
              let serverPublicKey = self.serverPublicKey
        else {
            verboseLog("[AltSign] GSAContext.makeVerificationMessage failed: salt or serverPublicKey is nil")
            return nil
        }

        verboseLog("[AltSign] GSAContext.makeVerificationMessage: generating verification message. Salt size: \(salt.count) bytes, ServerPubKey size: \(serverPublicKey.count) bytes, iterations: \(iterations), isHex: \(isHexadecimal)")
        guard let derivedPasswordKey = self.makeX(
            password: self.password,
            salt: salt,
            iterations: iterations,
            isHexadecimal: isHexadecimal
        )
        else {
            verboseLog("[AltSign] GSAContext.makeVerificationMessage failed: derivedPasswordKey generation failed")
            return nil
        }

        self.derivedPasswordKey = derivedPasswordKey

        self.verificationMessage = self.makeM1(
            username: self.username,
            derivedPasswordKey: derivedPasswordKey,
            salt: salt,
            serverPublicKey: serverPublicKey
        )

        if let msg = self.verificationMessage {
            verboseLog("[AltSign] GSAContext.makeVerificationMessage succeeded. Verification msg M1 size: \(msg.count) bytes")
        } else {
            verboseLog("[AltSign] GSAContext.makeVerificationMessage failed: makeM1 returned nil")
        }
        return self.verificationMessage
    }

    func verifyServerVerificationMessage(_ serverVerificationMessage: Data) -> Bool {
        guard !serverVerificationMessage.isEmpty else { return false }

        verboseLog("[AltSign] GSAContext.verifyServerVerificationMessage: verifying server proof of size \(serverVerificationMessage.count) bytes")
        let isValid = srp?.verifyServerProof(serverVerificationMessage) ?? false

        if isValid {
            self.sessionKey = srp?.sessionKey()
            verboseLog("[AltSign] GSAContext.verifyServerVerificationMessage: verification succeeded!")
        } else {
            verboseLog("[AltSign] GSAContext.verifyServerVerificationMessage: verification failed!")
        }

        return isValid
    }

    func makeChecksum(appName: String) -> Data? {
        guard let sessionKey = self.sessionKey,
              let dsid = self.dsid
        else {
            verboseLog("[AltSign] GSAContext.makeChecksum failed: sessionKey or dsid is nil")
            return nil
        }

        verboseLog("[AltSign] GSAContext.makeChecksum starting for appName: \(appName), dsid: \(dsid)")
        let checksum = CoreCryptoBridge.hmacSHA256(
            key: sessionKey,
            strings: ["apptokens", dsid, appName]
        )
        if let checksum = checksum {
            verboseLog("[AltSign] GSAContext.makeChecksum succeeded. Size: \(checksum.count) bytes")
        } else {
            verboseLog("[AltSign] GSAContext.makeChecksum failed: hmacSHA256 returned nil")
        }
        return checksum
    }
}

internal extension GSAContext {

    func makeHMACKey(_ string: String) -> Data? {
        guard let sessionKey = srp?.sessionKey() else {
            return nil
        }

        return CoreCryptoBridge.hmacSHA256(
            key: sessionKey,
            strings: [string]
        )
    }
}

private extension GSAContext {

    func makeAKey() -> Data? {
        return srp?.startAuthentication()
    }

    func makeX(password: String, salt: Data, iterations: Int, isHexadecimal: Bool) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }

        guard let digest = CoreCryptoBridge.sha256(passwordData) else { return nil }

        // s2k     : PBKDF2 password = raw SHA-256(password)            (32 bytes)
        // s2k_fo  : PBKDF2 password = lowercase hex string of that     (64 ASCII bytes)
        // NOTE: the old `digest.hexadecimal()` was a hex-string *decoder* fed raw
        // digest bytes, so it dropped everything and yielded an empty password →
        // Apple returned -22406 "enter the correct password". Encode, don't decode.
        let inputDigest: Data = isHexadecimal ? Data(digest.hexEncodedString().utf8) : digest

        return CoreCryptoBridge.pbkdf2SHA256(
            password: inputDigest,
            salt: salt,
            rounds: iterations,
            outputLength: digest.count
        )
    }

    func makeM1(username: String, derivedPasswordKey x: Data, salt: Data, serverPublicKey B: Data) -> Data? {
        return srp?.processChallenge(
            username: username,
            password: x,
            salt: salt,
            serverPublicKey: B
        )
    }
}

extension Data {

    /// Converts ASCII hex string data ("a1b2...") → raw bytes
    func hexadecimal() -> Data {
        var result = Data(capacity: count / 2)

        var buffer: UInt8 = 0
        var highNibble = true

        for byte in self {
            let value: UInt8

            switch byte {
            case 48...57:  value = byte - 48        // '0'–'9'
            case 65...70:  value = byte - 55        // 'A'–'F'
            case 97...102: value = byte - 87        // 'a'–'f'
            default: continue
            }

            if highNibble {
                buffer = value << 4
            } else {
                buffer |= value
                result.append(buffer)
            }

            highNibble.toggle()
        }

        return result
    }
}
