//
//  AltSign.swift
//  AltSign
//
//  Created by Magesh K on 28/06/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import SwiftBridge

public enum AltSign {
    public static var isLoggingEnabled: Bool {
        return AltSignLogging.isLoggingEnabled
    }

    public static func setLogging(_ enabled: Bool) {
        AltSignLogging.setLogging(enabled)
    }
}
