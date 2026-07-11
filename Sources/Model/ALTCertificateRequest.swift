//
//  ALTCertificateRequest.swift
//  AltSign
//

import Foundation
import SwiftBridge


public final class ALTCertificateRequest: NSObject {

    // MARK: Properties

    public let data: Data
    public let privateKey: Data

    // MARK: Init

    private init(data: Data, privateKey: Data) {
        self.data = data
        self.privateKey = privateKey
        super.init()
    }

    // MARK: Factory (matches ObjC API)


    public static func makeRequest() -> ALTCertificateRequest? {

        let subject = CertificatesManager.CSRSubject(
            country: "US",
            state: "CA",
            locality: "Los Angeles",
            organization: "AltSign",
            commonName: "AltSign"
        )

        guard let result = try? CertificatesManager.generateCSR(subject: subject)
        else { return nil }

        return ALTCertificateRequest(
            data: result.csr,
            privateKey: result.privateKey
        )
    }
}


