//
//  ALTAppGroup.swift
//  AltSign
//

import Foundation


public final class ALTAppGroup: NSObject {

    // MARK: Properties

    public let name: String
    public let identifier: String
    public let groupIdentifier: String

    // MARK: Init

    @objc(initWithResponseDictionary:)
    public init?(responseDictionary: [String: Any]) {

        guard
            let name = responseDictionary["name"] as? String,
            let identifier = responseDictionary["applicationGroup"] as? String,
            let groupIdentifier = responseDictionary["identifier"] as? String
        else {
            return nil
        }

        self.name = name
        self.identifier = identifier
        self.groupIdentifier = groupIdentifier

        super.init()
    }

    // MARK: NSObject

    public override var description: String {
        "<\(NSStringFromClass(Swift.type(of: self))): \(Unmanaged.passUnretained(self).toOpaque()), ID: \(identifier), GroupID: \(groupIdentifier)>"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? ALTAppGroup else {
            return false
        }

        return identifier == other.identifier &&
               groupIdentifier == other.groupIdentifier
    }

    public override var hash: Int {
        identifier.hashValue ^ groupIdentifier.hashValue
    }
}
