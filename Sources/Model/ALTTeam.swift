//
//  ALTTeam.swift
//  AltSign
//

import Foundation

@objc
public enum ALTTeamType: Int {
    case unknown = 0
    case organization
    case individual
    case free
}


public final class ALTTeam: NSObject {

    // MARK: Public Properties

    public let name: String
    public let identifier: String
    public let type: ALTTeamType
    public let account: ALTAccount

    // MARK: Designated Init (matches ObjC)

    @objc
    public init(
        name: String,
        identifier: String,
        type: ALTTeamType,
        account: ALTAccount
    ) {
        self.name = name
        self.identifier = identifier
        self.type = type
        self.account = account
        super.init()
    }

    // MARK: Apple API Init

    @objc(initWithAccount:responseDictionary:)
    public convenience init?(
        account: ALTAccount,
        responseDictionary: [String: Any]
    ) {

        guard
            let name = responseDictionary["name"] as? String,
            let identifier = responseDictionary["teamId"] as? String,
            let teamType = responseDictionary["type"] as? String
        else {
            return nil
        }

        let resolvedType: ALTTeamType

        if teamType == "Company/Organization" {
            resolvedType = .organization
        }
        else if teamType == "Individual" {

            let memberships =
                responseDictionary["memberships"] as? [[String: Any]] ?? []

            if memberships.count == 1,
               let membershipName =
                    memberships.first?["name"] as? String,
               membershipName.lowercased().contains("free") {

                resolvedType = .free
            }
            else {
                resolvedType = .individual
            }
        }
        else {
            resolvedType = .unknown
        }

        self.init(
            name: name,
            identifier: identifier,
            type: resolvedType,
            account: account
        )
    }

    // MARK: NSObject Overrides

    public override var description: String {
        "<\(NSStringFromClass(Swift.type(of: self))): \(Unmanaged.passUnretained(self).toOpaque()), Name: \(name)>"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? ALTTeam else {
            return false
        }
        return identifier == other.identifier
    }

    public override var hash: Int {
        identifier.hashValue
    }
}
