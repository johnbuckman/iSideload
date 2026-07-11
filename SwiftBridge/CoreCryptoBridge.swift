//
//  CoreCryptoBridge.swift
//  AltSign
//

import Foundation
import NativeBridge
import CryptoKit
import CommonCrypto

public enum CoreCryptoBridge {

    public final class SRP {
        private let ctx: ccsrp_context
        public init?() {
            verboseLog("[AltSign] CoreCryptoBridge.SRP.init started")
            guard let c = native_bridge_ccsrp_client_new() else {
                debugLog("[AltSign] CoreCryptoBridge.SRP.init failed: native_bridge_ccsrp_client_new returned null")
                return nil
            }
            self.ctx = c
            verboseLog("[AltSign] CoreCryptoBridge.SRP.init completed successfully")
        }

        deinit {
            verboseLog("[AltSign] CoreCryptoBridge.SRP.deinit deallocating context")
            native_bridge_ccsrp_client_free(ctx)
        }

        /// Controlled escape hatch to pass the raw handle to lower-level callers
        public var rawHandle: OpaquePointer {
            OpaquePointer(ctx)
        }

        /// Returns the byte size of the SRP public key (A or B) for this group
        public func exchangeSize() -> Int {
            Int(native_bridge_ccsrp_exchange_size(ctx))
        }

        /// Generates and returns the client public key A
        public func startAuthentication() -> Data? {
            let size = exchangeSize()
            verboseLog("[AltSign] CoreCryptoBridge.SRP.startAuthentication starting. Exchange size: \(size)")
            var A = Data(count: size)

            let result = A.withUnsafeMutableBytes {
                native_bridge_ccsrp_client_start_authentication(
                    ctx,
                    $0.baseAddress,
                    nil // use system default RNG
                )
            }

            if result == 0 {
                verboseLog("[AltSign] CoreCryptoBridge.SRP.startAuthentication succeeded. Public key size: \(A.count) bytes")
                return A
            } else {
                debugLog("[AltSign] CoreCryptoBridge.SRP.startAuthentication failed with native error: \(result)")
                return nil
            }
        }

        /// Processes the server's salt and public key B; returns the client proof M1
        public func processChallenge(username: String, password: Data, salt: Data, serverPublicKey: Data) -> Data? {

            let size = Int(native_bridge_ccsrp_get_session_key_length(ctx))

            verboseLog("""
            [AltSign] CoreCryptoBridge.SRP.processChallenge starting:
              • Username: \(username)
              • Password size: \(password.count) bytes
              • Salt size: \(salt.count) bytes
              • Server Public Key size: \(serverPublicKey.count) bytes
              • Session Key Length: \(size)
            """)

            var M1 = Data(count: size)

            let result = M1.withUnsafeMutableBytes { m1Bytes in
                salt.withUnsafeBytes { saltBytes in
                    serverPublicKey.withUnsafeBytes { bBytes in
                        password.withUnsafeBytes { pwdBytes in
                            native_bridge_ccsrp_client_process_challenge(
                                ctx,
                                saltBytes.baseAddress,
                                salt.count,
                                bBytes.baseAddress,
                                serverPublicKey.count,
                                username,
                                pwdBytes.baseAddress,
                                password.count,
                                m1Bytes.baseAddress
                            )
                        }
                    }
                }
            }

            if result == 0 {
                verboseLog("[AltSign] CoreCryptoBridge.SRP.processChallenge succeeded. M1 size: \(M1.count) bytes")
                return M1
            } else {
                debugLog("[AltSign] CoreCryptoBridge.SRP.processChallenge failed with native error: \(result)")
                return nil
            }
        }

        /// Verifies the server's proof M2 and, if valid, stores the session key
        public func verifyServerProof(_ proof: Data) -> Bool {
            verboseLog("[AltSign] CoreCryptoBridge.SRP.verifyServerProof started. Proof size: \(proof.count) bytes")
            let result = proof.withUnsafeBytes {
                native_bridge_ccsrp_client_verify_session(ctx, $0.baseAddress) != 0
            }
            verboseLog("[AltSign] CoreCryptoBridge.SRP.verifyServerProof validation result: \(result)")
            return result
        }

        /// Returns the shared session key K established after a successful handshake
        public func sessionKey() -> Data? {
            verboseLog("[AltSign] CoreCryptoBridge.SRP.sessionKey requested")
            guard let ptr = native_bridge_ccsrp_get_session_key(ctx) else {
                debugLog("[AltSign] CoreCryptoBridge.SRP.sessionKey failed: native returned null session key pointer")
                return nil
            }
            let len = Int(native_bridge_ccsrp_get_session_key_length(ctx))
            let key = Data(bytes: ptr, count: len)
            verboseLog("[AltSign] CoreCryptoBridge.SRP.sessionKey retrieved. Key size: \(key.count) bytes")
            return key
        }
    }


    /// Computes HMAC-SHA256 over the concatenated UTF-8 encodings of `strings`
    public static func hmacSHA256(key: Data, strings: [String]) -> Data? {
        verboseLog("[AltSign] CoreCryptoBridge.hmacSHA256 started. Key size: \(key.count) bytes, strings: \(strings)")

        var hmac = HMAC<SHA256>(key: SymmetricKey(data: key))
        for s in strings {
            hmac.update(data: Data(s.utf8))
        }
        let mac = hmac.finalize()
        let out = Data(mac)
        verboseLog("[AltSign] CoreCryptoBridge.hmacSHA256 succeeded. Output size: \(out.count) bytes")
        return out
    }


    // MARK: - SHA256 Digest (CryptoKit)

    /// Returns the SHA-256 digest of `data`
    public static func sha256(_ data: Data) -> Data? {
        verboseLog("[AltSign] CoreCryptoBridge.sha256 started. Data size: \(data.count) bytes")
        let digest = SHA256.hash(data: data)
        let out = Data(digest)
        verboseLog("[AltSign] CoreCryptoBridge.sha256 succeeded. Hash: \(out.hexEncodedString())")
        return out
    }

    /// Derives a key from a password using PBKDF2-HMAC-SHA256
    public static func pbkdf2SHA256(
        password: Data,
        salt: Data,
        rounds: Int,
        outputLength: Int
    ) -> Data? {
        verboseLog("[AltSign] CoreCryptoBridge.pbkdf2SHA256 started. Password size: \(password.count) bytes, salt size: \(salt.count) bytes, rounds: \(rounds), outputLength: \(outputLength)")

        var out = Data(count: outputLength)

        let result = out.withUnsafeMutableBytes { outBytes in
            password.withUnsafeBytes { pwdBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pwdBytes.bindMemory(to: Int8.self).baseAddress,
                        password.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(rounds),
                        outBytes.bindMemory(to: UInt8.self).baseAddress,
                        outputLength
                    )
                }
            }
        }

        if result == kCCSuccess {
            verboseLog("[AltSign] CoreCryptoBridge.pbkdf2SHA256 succeeded. Output size: \(out.count) bytes")
            return out
        } else {
            debugLog("[AltSign] CoreCryptoBridge.pbkdf2SHA256 failed with CCCrypt error: \(result)")
            return nil
        }
    }

    public static func aesCBCDecrypt(key: Data, iv: Data, ciphertext: Data) -> Data? {
        verboseLog("""
        [AltSign] CoreCryptoBridge.aesCBCDecrypt started:
          • Key size: \(key.count) bytes
          • IV size: \(iv.count) bytes
          • Ciphertext size: \(ciphertext.count) bytes
        """)

        var out = Data(count: ciphertext.count + kCCBlockSizeAES128) // worst-case output
        var outLen = 0
        let outCapacity = out.count

        let result = out.withUnsafeMutableBytes { outBytes in
            ciphertext.withUnsafeBytes { inBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, key.count,
                            ivBytes.baseAddress,
                            inBytes.baseAddress, ciphertext.count,
                            outBytes.baseAddress, outCapacity,
                            &outLen
                        )
                    }
                }
            }
        }

        if result == kCCSuccess {
            let decrypted = out.prefix(outLen)
            verboseLog("[AltSign] CoreCryptoBridge.aesCBCDecrypt succeeded. Decrypted size: \(decrypted.count) bytes")
            return decrypted
        } else {
            debugLog("[AltSign] CoreCryptoBridge.aesCBCDecrypt failed with CCCrypt error: \(result)")
            return nil
        }
    }
    
    // MARK: - AES GCM

    /// Decrypts `ciphertext` with AES-GCM using the given `key`, `nonce`, `aad`, and authentication `tag`
    public static func aesGCMDecrypt(
        key: Data,
        nonce: Data,
        aad: Data,
        ciphertext: Data,
        tag: Data
    ) -> Data? {

        verboseLog("""
        [AltSign] CoreCryptoBridge.aesGCMDecrypt started:
          • Key size: \(key.count) bytes
          • Nonce size: \(nonce.count) bytes
          • AAD size: \(aad.count) bytes
          • Ciphertext size: \(ciphertext.count) bytes
          • Tag size: \(tag.count) bytes
        """)

        do {
            let symmetricKey = SymmetricKey(data: key)
            let gcmNonce = try AES.GCM.Nonce(data: nonce)

            // CryptoKit expects the ciphertext and tag concatenated
            let combined = ciphertext + tag
            let sealedBox = try AES.GCM.SealedBox(
                nonce: gcmNonce,
                ciphertext: ciphertext,
                tag: tag
            )

            let out = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
            verboseLog("[AltSign] CoreCryptoBridge.aesGCMDecrypt succeeded. Decrypted size: \(out.count) bytes")
            return out
        } catch {
            debugLog("[AltSign] CoreCryptoBridge.aesGCMDecrypt failed: \(error)")
            return nil
        }
    }
}

public extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
