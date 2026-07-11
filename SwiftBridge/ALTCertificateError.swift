//
//  ALTCertificateError.swift
//  AltSign
//
//  Created by Magesh K.
//

import Foundation

public enum ALTCertificateError: LocalizedError, Equatable {
    case invalidFormat(cause: String? = nil)          // Wrong ASN.1 tag sequence (e.g. raw certificate passed)
    case decryptionFailed(cause: String? = nil)       // Wrong password (MAC verify/generation failure)
    case extractionFailed(cause: String? = nil)       // General parsing or null pointer failure
    case memoryAllocationFailed(cause: String? = nil) // Out of memory or allocation failed
    
    public var errorDescription: String? {
        let base: String
        let cause: String?
        switch self {
        case .invalidFormat(let c):
            base = "The data is not in PKCS12 format."
            cause = c
        case .decryptionFailed(let c):
            base = "Decryption failed. Please check if the password is correct."
            cause = c
        case .extractionFailed(let c):
            base = "Failed to extract certificate or private key from PKCS12 archive."
            cause = c
        case .memoryAllocationFailed(let c):
            base = "Out of memory. Memory allocation failed during PKCS12 extraction."
            cause = c
        }
        if let cause = cause {
            return "\(base)\ncause: \(cause)"
        }
        return base
    }
    
    public static func ~= (lhs: ALTCertificateError, rhs: Error) -> Bool {
        guard let error = rhs as? ALTCertificateError else { return false }
        switch (lhs, error) {
        case (.invalidFormat, .invalidFormat): return true
        case (.decryptionFailed, .decryptionFailed): return true
        case (.extractionFailed, .extractionFailed): return true
        case (.memoryAllocationFailed, .memoryAllocationFailed): return true
        default: return false
        }
    }
}
