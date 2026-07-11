// Runtime proof of the SwiftPM signing path:
//   LdidBridge.sign  ->  native_bridge_ldid_sign (shim)  ->  native_bridge_zsign_sign  ->  zsign
// Usage: swift run ZsignTest <app-folder> <p12>
import Foundation
import SwiftBridge

let args = CommandLine.arguments
guard args.count >= 3 else {
    FileHandle.standardError.write(Data("usage: ZsignTest <app> <p12>\n".utf8))
    exit(64)
}
let appPath = args[1]
let keyData = try! Data(contentsOf: URL(fileURLWithPath: args[2]))

do {
    try LdidBridge.sign(
        appPath: appPath,
        keyData: keyData,
        entitlementProvider: { _ in "" },
        progress: { }
    )
    print(">>> SWIFT LdidBridge.sign OK (zsign ran via the SwiftPM package)")
} catch {
    print(">>> SWIFT LdidBridge.sign FAILED: \(error)")
    exit(1)
}
