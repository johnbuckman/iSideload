//
//  ALTAppID.swift
//  AltSign
//

import Foundation


public final class ALTAppID: NSObject, NSCopying {

    // MARK: Properties

    public var name: String
    public var identifier: String
    public var bundleIdentifier: String
    public var expirationDate: Date?

    public var features: [ALTFeature: Any]
    public var entitlements: [ALTEntitlement: Any]
    public var capabilities: [ALTCapability: Any] = [:]

    // MARK: Designated Init

    @objc
    public init(
        name: String,
        identifier: String,
        bundleIdentifier: String,
        expirationDate: Date?,
        features: [ALTFeature: Any]
    ) {
        self.name = name
        self.identifier = identifier
        self.bundleIdentifier = bundleIdentifier
        self.expirationDate = expirationDate
        self.features = features
        self.entitlements = [:]
        super.init()
    }

    // MARK: Apple API Init

    @objc(initWithResponseDictionary:)
    public convenience init?(responseDictionary: [String: Any]) {

        guard
            let name = responseDictionary["name"] as? String,
            let identifier = responseDictionary["appIdId"] as? String,
            let bundleIdentifier = responseDictionary["identifier"] as? String
        else {
            return nil
        }

        let allFeatures =
            responseDictionary["features"] as? [ALTFeature: Any] ?? [:]

        let enabledFeatures =
            responseDictionary["enabledFeatures"] as? [ALTFeature] ?? []

        var resolvedFeatures: [ALTFeature: Any] = [:]

        for feature in enabledFeatures {
            resolvedFeatures[feature] = allFeatures[feature]
        }

        let expirationDate =
            responseDictionary["expirationDate"] as? Date

        self.init(
            name: name,
            identifier: identifier,
            bundleIdentifier: bundleIdentifier,
            expirationDate: expirationDate,
            features: resolvedFeatures
        )
    }

    // MARK: NSObject

    public override var description: String {
        "<\(NSStringFromClass(Swift.type(of: self))): \(Unmanaged.passUnretained(self).toOpaque()), Name: \(name), ID: \(identifier), BundleID: \(bundleIdentifier)>"
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let other = object as? ALTAppID else {
            return false
        }

        return identifier == other.identifier &&
               bundleIdentifier == other.bundleIdentifier
    }

    public override var hash: Int {
        identifier.hashValue ^ bundleIdentifier.hashValue
    }

    // MARK: NSCopying

    public func copy(with zone: NSZone? = nil) -> Any {
        ALTAppID(
            name: name,
            identifier: identifier,
            bundleIdentifier: bundleIdentifier,
            expirationDate: expirationDate,
            features: features
        )
    }
}
