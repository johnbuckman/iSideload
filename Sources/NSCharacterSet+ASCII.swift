//
//  NSCharacterSet+ASCII.swift
//  AltSign
//

import Foundation

extension CharacterSet {

    /// Equivalent to +asciiAlphanumericCharacterSet
    /// Apple's servers only accept ASCII alphanumerics.

    public static var asciiAlphanumericCharacterSet: CharacterSet {
        CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        )
    }
}
