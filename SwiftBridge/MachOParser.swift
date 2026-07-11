//
//  MachOParser.swift
//  AltSign
//
//  Created by Magesh K on 07/07/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import CryptoKit
import Security

public enum MachOParserError: Error {
    case invalidMachO       // The binary structure is invalid or malformed.
    case missingSignature   // The binary does not contain a code signature block.
}

/**
 Swift Parser for extracting code signature metadata and other binary information
 from single-arch (thin) and multi-arch (FAT) Mach-O binaries 
 based on public Mach-O specification.
 */
public final class MachOParser {

    public let url: URL?
    private let data: Data

    // Magic constants
    private static let FAT_MAGIC: UInt32 = 0xcafebabe       // FAT binary magic (Big-Endian)
    private static let FAT_CIGAM: UInt32 = 0xbebafeca       // FAT binary magic (Little-Endian)
    private static let FAT_MAGIC_64: UInt32 = 0xcafebabf    // 64-bit FAT binary magic (Big-Endian)
    private static let FAT_CIGAM_64: UInt32 = 0xbfbafeca    // 64-bit FAT binary magic (Little-Endian)

    private static let MH_MAGIC: UInt32 = 0xfeedface        // 32-bit Mach-O magic (Big-Endian)
    private static let MH_CIGAM: UInt32 = 0xcefaedfe        // 32-bit Mach-O magic (Little-Endian)
    private static let MH_MAGIC_64: UInt32 = 0xfeedfacf     // 64-bit Mach-O magic (Big-Endian)
    private static let MH_CIGAM_64: UInt32 = 0xcffaedfe     // 64-bit Mach-O magic (Little-Endian)

    private static let LC_CODE_SIGNATURE: UInt32 = 0x1d     // Load command type for code signatures
    private static let LC_LOAD_DYLIB: UInt32 = 0x0c          // Load command type for load dylib
    private static let LC_ENCRYPTION_INFO: UInt32 = 0x21     // Load command type for encryption info
    private static let LC_ENCRYPTION_INFO_64: UInt32 = 0x2c  // Load command type for encryption info (64-bit)
    private static let LC_MAIN: UInt32 = 0x28 | 0x80000000   // Load command type for entry point offset
    private static let LC_SEGMENT: UInt32 = 0x01             // Load command type for 32-bit segment
    private static let LC_SEGMENT_64: UInt32 = 0x19          // Load command type for 64-bit segment
    private static let LC_VERSION_MIN_IPHONEOS: UInt32 = 0x25 // Load command type for min iOS version
    private static let LC_VERSION_MIN_MACOSX: UInt32 = 0x24   // Load command type for min macOS version
    private static let LC_VERSION_MIN_TVOS: UInt32 = 0x2f     // Load command type for min tvOS version
    private static let LC_VERSION_MIN_WATCHOS: UInt32 = 0x30  // Load command type for min watchOS version
    private static let LC_BUILD_VERSION: UInt32 = 0x32       // Load command type for build version (iOS 12+)

    private static let SUPERBLOB_MAGIC: UInt32 = 0xfade0cc0  // SuperBlob signature magic
    private static let BLOB_MAGIC_REQ: UInt32 = 0xfade7171   // Requirements blob magic
    private static let BLOB_MAGIC_ENT: UInt32 = 0xfade7172   // Entitlements blob magic

    /**
     Initializes the parser with a local binary file URL.
     */
    public init(url: URL) throws {
        self.url = url
        self.data = try Data(contentsOf: url, options: .mappedIfSafe)
    }

    /**
     Initializes the parser directly with binary data.
     */
    public init(data: Data) {
        self.url = nil
        self.data = data
    }

    /**
     Returns the subdata of the thin binary slice matching the given criteria.
     Defaults to the arm64 slice if available, or the first valid slice.
     */
    public func getThinBinaryData() throws -> Data {
        guard data.count >= 4 else { throw MachOParserError.invalidMachO }
        let magic = data.readUInt32(at: 0)
        
        if magic == Self.FAT_MAGIC || magic == Self.FAT_CIGAM || magic == Self.FAT_MAGIC_64 || magic == Self.FAT_CIGAM_64 {
            let swap = (magic == Self.FAT_CIGAM || magic == Self.FAT_CIGAM_64)
            let is64 = (magic == Self.FAT_MAGIC_64 || magic == Self.FAT_CIGAM_64)
            
            let numArchs = swap ? data.readUInt32(at: 4).byteSwapped : data.readUInt32(at: 4)
            let archHeaderSize = is64 ? 32 : 20
            
            var bestSliceData: Data? = nil
            
            for i in 0..<Int(numArchs) {
                let offset = 8 + i * archHeaderSize
                let sliceCpuType = swap ? data.readUInt32(at: offset).byteSwapped : data.readUInt32(at: offset)
                
                let sliceOffset = is64 ?
                    (swap ? data.readUInt64(at: offset + 8).byteSwapped : data.readUInt64(at: offset + 8)) :
                    UInt64(swap ? data.readUInt32(at: offset + 8).byteSwapped : data.readUInt32(at: offset + 8))
                
                let sliceSize = is64 ?
                    (swap ? data.readUInt64(at: offset + 16).byteSwapped : data.readUInt64(at: offset + 16)) :
                    UInt64(swap ? data.readUInt32(at: offset + 12).byteSwapped : data.readUInt32(at: offset + 12))
                
                guard Int(sliceOffset) + Int(sliceSize) <= data.count else { continue }
                let sliceData = data.subdata(in: Int(sliceOffset)..<Int(sliceOffset + sliceSize))
                
                // Prefer ARM64 slice (cpu type 12 | 0x01000000 = 16777228)
                if sliceCpuType == 16777228 {
                    return sliceData
                }
                
                if bestSliceData == nil {
                    bestSliceData = sliceData
                }
            }
            if let bestSliceData {
                return bestSliceData
            }
            throw MachOParserError.invalidMachO
        } else {
            return data
        }
    }

    /**
     Extracts the XML entitlements string from the binary.
     */
    public func entitlements() throws -> String {
        let blob = try extractRawBlob(slotType: 5) // CSSLOT_ENTITLEMENTS = 5
        guard blob.count >= 8 else { throw MachOParserError.invalidMachO }
        let payload = blob.subdata(in: 8..<blob.count)
        guard let result = String(data: payload, encoding: .utf8) else {
            throw MachOParserError.invalidMachO
        }
        return result
    }

    /**
     Extracts the requirements string from the binary.
     */
    public func requirements() throws -> String {
        let blob = try extractRawBlob(slotType: 2) // CSSLOT_REQUIREMENTS = 2
        guard blob.count >= 8 else { throw MachOParserError.invalidMachO }
        let payload = blob.subdata(in: 8..<blob.count)
        guard let result = String(data: payload, encoding: .utf8) else {
            throw MachOParserError.invalidMachO
        }
        return result
    }

    /**
     Computes the CDHash (Code Directory Hash) of the binary.
     */
    public func cdHash() -> Data? {
        guard let cdBlob = try? extractRawBlob(slotType: 0) else { return nil } // CSSLOT_CODEDIRECTORY = 0
        guard cdBlob.count >= 40 else { return nil }
        
        let hashType = cdBlob[37] // offset 37 of CodeDirectory contains hashType
        // hashType: 1 = SHA-1, 2 = SHA-256
        if hashType == 1 {
            let digest = Insecure.SHA1.hash(data: cdBlob)
            return Data(digest)
        } else if hashType == 2 {
            let digest = SHA256.hash(data: cdBlob)
            return Data(digest)
        }
        return nil
    }

    /**
     Extracts the Team ID of the signer from the Code Directory blob.
     */
    public func teamID() -> String? {
        guard let cdBlob = try? extractRawBlob(slotType: 0) else { return nil }
        guard cdBlob.count >= 40 else { return nil }
        
        let version = cdBlob.readUInt32BigEndian(at: 8)
        guard version >= 0x20200 else { return nil } // Team ID is only available in version >= 2.2
        
        let teamOffset = cdBlob.readUInt32BigEndian(at: 32)
        guard teamOffset > 0, teamOffset < cdBlob.count else { return nil }
        
        let teamData = cdBlob.subdata(in: Int(teamOffset)..<cdBlob.count)
        // Read null-terminated string
        if let nullIndex = teamData.firstIndex(of: 0) {
            let actualTeamData = teamData.prefix(upTo: nullIndex)
            return String(data: actualTeamData, encoding: .utf8)
        }
        return String(data: teamData, encoding: .utf8)
    }

    /**
     Extracts the certificate chain used to sign the binary.
     */
    public func certificates() -> [SecCertificate] {
        guard let signatureBlob = try? extractRawBlob(slotType: 0x10000) else { return [] } // CSSLOT_SIGNATURESLOT = 0x10000
        guard signatureBlob.count >= 8 else { return [] }
        let payload = signatureBlob.subdata(in: 8..<signatureBlob.count)
        
        let certDatas = ASN1Decoder.findCertificates(in: payload)
        return certDatas.compactMap { certData in
            SecCertificateCreateWithData(nil, certData as CFData)
        }
    }

    /**
     Lists the CPU architectures present in the binary.
     */
    public func architectures() -> [String] {
        guard data.count >= 4 else { return [] }
        let magic = data.readUInt32(at: 0)
        
        if magic == Self.FAT_MAGIC || magic == Self.FAT_CIGAM || magic == Self.FAT_MAGIC_64 || magic == Self.FAT_CIGAM_64 {
            let swap = (magic == Self.FAT_CIGAM || magic == Self.FAT_CIGAM_64)
            let is64 = (magic == Self.FAT_MAGIC_64 || magic == Self.FAT_CIGAM_64)
            
            let numArchs = swap ? data.readUInt32(at: 4).byteSwapped : data.readUInt32(at: 4)
            let archHeaderSize = is64 ? 32 : 20
            
            var list = [String]()
            for i in 0..<Int(numArchs) {
                let offset = 8 + i * archHeaderSize
                let sliceCpuType = swap ? data.readUInt32(at: offset).byteSwapped : data.readUInt32(at: offset)
                let sliceCpuSubtype = swap ? data.readUInt32(at: offset + 4).byteSwapped : data.readUInt32(at: offset + 4)
                list.append(cpuName(type: sliceCpuType, subtype: sliceCpuSubtype))
            }
            return list
        } else if magic == Self.MH_MAGIC || magic == Self.MH_CIGAM || magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64 {
            let swap = (magic == Self.MH_CIGAM || magic == Self.MH_CIGAM_64)
            let sliceCpuType = swap ? data.readUInt32(at: 4).byteSwapped : data.readUInt32(at: 4)
            let sliceCpuSubtype = swap ? data.readUInt32(at: 8).byteSwapped : data.readUInt32(at: 8)
            return [cpuName(type: sliceCpuType, subtype: sliceCpuSubtype)]
        }
        return []
    }

    /**
     Extracts the minimum OS version required to run this binary.
     */
    public func minimumOSVersion() -> String? {
        guard let thinData = try? getThinBinaryData() else { return nil }
        guard thinData.count >= 28 else { return nil }
        let magic = thinData.readUInt32(at: 0)
        let swap = (magic == Self.MH_CIGAM || magic == Self.MH_CIGAM_64)
        let is64 = (magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64)
        let ncmds = swap ? thinData.readUInt32(at: 16).byteSwapped : thinData.readUInt32(at: 16)
        let headerSize = is64 ? 32 : 28
        
        var offset = headerSize
        for _ in 0..<Int(ncmds) {
            guard offset + 8 <= thinData.count else { break }
            let cmd = swap ? thinData.readUInt32(at: offset).byteSwapped : thinData.readUInt32(at: offset)
            let cmdsize = swap ? thinData.readUInt32(at: offset + 4).byteSwapped : thinData.readUInt32(at: offset + 4)
            
            if cmd == Self.LC_VERSION_MIN_IPHONEOS || cmd == Self.LC_VERSION_MIN_MACOSX || cmd == Self.LC_VERSION_MIN_TVOS || cmd == Self.LC_VERSION_MIN_WATCHOS {
                guard offset + 12 <= thinData.count else { break }
                let version = swap ? thinData.readUInt32(at: offset + 8).byteSwapped : thinData.readUInt32(at: offset + 8)
                return formatVersion(version)
            } else if cmd == Self.LC_BUILD_VERSION {
                guard offset + 16 <= thinData.count else { break }
                let minos = swap ? thinData.readUInt32(at: offset + 12).byteSwapped : thinData.readUInt32(at: offset + 12)
                return formatVersion(minos)
            }
            offset += Int(cmdsize)
        }
        return nil
    }

    private func cpuName(type: UInt32, subtype: UInt32) -> String {
        switch type {
        case 7:
            return "i386"
        case 16777223:
            return "x86_64"
        case 12:
            switch subtype {
            case 9: return "armv7"
            case 11: return "armv7s"
            default: return "arm"
            }
        case 16777228:
            switch subtype {
            case 2: return "arm64e"
            default: return "arm64"
            }
        default:
            return "Unknown (\(type))"
        }
    }

    private func formatVersion(_ version: UInt32) -> String {
        let major = (version >> 16) & 0xFFFF
        let minor = (version >> 8) & 0xFF
        let patch = version & 0xFF
        return "\(major).\(minor).\(patch)"
    }


    /**
     Identifies the target platform type (e.g. iOS, macOS, tvOS, watchOS).
     */
    public func platformType() -> String? {
        guard let thinData = try? getThinBinaryData() else { return nil }
        guard thinData.count >= 28 else { return nil }
        let magic = thinData.readUInt32(at: 0)
        let swap = (magic == Self.MH_CIGAM || magic == Self.MH_CIGAM_64)
        let is64 = (magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64)
        let ncmds = swap ? thinData.readUInt32(at: 16).byteSwapped : thinData.readUInt32(at: 16)
        let headerSize = is64 ? 32 : 28
        
        var offset = headerSize
        for _ in 0..<Int(ncmds) {
            guard offset + 8 <= thinData.count else { break }
            let cmd = swap ? thinData.readUInt32(at: offset).byteSwapped : thinData.readUInt32(at: offset)
            let cmdsize = swap ? thinData.readUInt32(at: offset + 4).byteSwapped : thinData.readUInt32(at: offset + 4)
            
            if cmd == Self.LC_VERSION_MIN_IPHONEOS {
                return "iOS"
            } else if cmd == Self.LC_VERSION_MIN_MACOSX {
                return "macOS"
            } else if cmd == Self.LC_VERSION_MIN_TVOS {
                return "tvOS"
            } else if cmd == Self.LC_VERSION_MIN_WATCHOS {
                return "watchOS"
            } else if cmd == Self.LC_BUILD_VERSION {
                guard offset + 12 <= thinData.count else { break }
                let platform = swap ? thinData.readUInt32(at: offset + 8).byteSwapped : thinData.readUInt32(at: offset + 8)
                switch platform {
                case 1: return "macOS"
                case 2: return "iOS"
                case 3: return "tvOS"
                case 4: return "watchOS"
                case 6: return "iOS Simulator"
                case 7: return "tvOS Simulator"
                case 8: return "watchOS Simulator"
                case 9: return "macCatalyst"
                default: return "unknown"
                }
            }
            offset += Int(cmdsize)
        }
        return nil
    }

    /**
     Lists the paths of all linked dynamic libraries (dylibs) in the binary.
     */
    public func linkedLibraries() -> [String] {
        guard let thinData = try? getThinBinaryData() else { return [] }
        guard thinData.count >= 28 else { return [] }
        let magic = thinData.readUInt32(at: 0)
        let swap = (magic == Self.MH_CIGAM || magic == Self.MH_CIGAM_64)
        let is64 = (magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64)
        let ncmds = swap ? thinData.readUInt32(at: 16).byteSwapped : thinData.readUInt32(at: 16)
        let headerSize = is64 ? 32 : 28
        
        var list = [String]()
        var offset = headerSize
        for _ in 0..<Int(ncmds) {
            guard offset + 8 <= thinData.count else { break }
            let cmd = swap ? thinData.readUInt32(at: offset).byteSwapped : thinData.readUInt32(at: offset)
            let cmdsize = swap ? thinData.readUInt32(at: offset + 4).byteSwapped : thinData.readUInt32(at: offset + 4)
            
            if cmd == Self.LC_LOAD_DYLIB {
                guard offset + 12 <= thinData.count else { break }
                let nameOffset = swap ? thinData.readUInt32(at: offset + 8).byteSwapped : thinData.readUInt32(at: offset + 8)
                let nameStart = offset + Int(nameOffset)
                guard nameStart < thinData.count else { break }
                let pathData = thinData.subdata(in: nameStart..<offset + Int(cmdsize))
                if let nullIndex = pathData.firstIndex(of: 0) {
                    let actualPathData = pathData.prefix(upTo: nullIndex)
                    if let path = String(data: actualPathData, encoding: .utf8) {
                        list.append(path)
                    }
                } else if let path = String(data: pathData, encoding: .utf8) {
                    list.append(path)
                }
            }
            offset += Int(cmdsize)
        }
        return list
    }

    /**
     Checks if the binary is encrypted with FairPlay DRM.
     */
    public func isEncrypted() -> Bool {
        guard let thinData = try? getThinBinaryData() else { return false }
        guard thinData.count >= 28 else { return false }
        let magic = thinData.readUInt32(at: 0)
        let swap = (magic == Self.MH_CIGAM || magic == Self.MH_CIGAM_64)
        let is64 = (magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64)
        let ncmds = swap ? thinData.readUInt32(at: 16).byteSwapped : thinData.readUInt32(at: 16)
        let headerSize = is64 ? 32 : 28
        
        var offset = headerSize
        for _ in 0..<Int(ncmds) {
            guard offset + 8 <= thinData.count else { break }
            let cmd = swap ? thinData.readUInt32(at: offset).byteSwapped : thinData.readUInt32(at: offset)
            let cmdsize = swap ? thinData.readUInt32(at: offset + 4).byteSwapped : thinData.readUInt32(at: offset + 4)
            
            if cmd == Self.LC_ENCRYPTION_INFO || cmd == Self.LC_ENCRYPTION_INFO_64 {
                guard offset + 20 <= thinData.count else { break }
                let cryptid = swap ? thinData.readUInt32(at: offset + 16).byteSwapped : thinData.readUInt32(at: offset + 16)
                return cryptid != 0
            }
            offset += Int(cmdsize)
        }
        return false
    }

    /**
     Extracts the execution entry point offset from the binary.
     */
    public func entryPoint() -> UInt64? {
        guard let thinData = try? getThinBinaryData() else { return nil }
        guard thinData.count >= 28 else { return nil }
        let magic = thinData.readUInt32(at: 0)
        let swap = (magic == Self.MH_CIGAM || magic == Self.MH_CIGAM_64)
        let is64 = (magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64)
        let ncmds = swap ? thinData.readUInt32(at: 16).byteSwapped : thinData.readUInt32(at: 16)
        let headerSize = is64 ? 32 : 28
        
        var offset = headerSize
        for _ in 0..<Int(ncmds) {
            guard offset + 8 <= thinData.count else { break }
            let cmd = swap ? thinData.readUInt32(at: offset).byteSwapped : thinData.readUInt32(at: offset)
            let cmdsize = swap ? thinData.readUInt32(at: offset + 4).byteSwapped : thinData.readUInt32(at: offset + 4)
            
            if cmd == Self.LC_MAIN {
                guard offset + 16 <= thinData.count else { break }
                let entryoff = swap ? thinData.readUInt64(at: offset + 8).byteSwapped : thinData.readUInt64(at: offset + 8)
                return entryoff
            }
            offset += Int(cmdsize)
        }
        return nil
    }

    /**
     Lists the segments parsed from the binary load commands.
     */
    public func segments() -> [(name: String, offset: UInt64, size: UInt64)] {
        guard let thinData = try? getThinBinaryData() else { return [] }
        guard thinData.count >= 28 else { return [] }
        let magic = thinData.readUInt32(at: 0)
        let swap = (magic == Self.MH_CIGAM || magic == Self.MH_CIGAM_64)
        let is64 = (magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64)
        let ncmds = swap ? thinData.readUInt32(at: 16).byteSwapped : thinData.readUInt32(at: 16)
        let headerSize = is64 ? 32 : 28
        
        var list = [(name: String, offset: UInt64, size: UInt64)]()
        var offset = headerSize
        for _ in 0..<Int(ncmds) {
            guard offset + 8 <= thinData.count else { break }
            let cmd = swap ? thinData.readUInt32(at: offset).byteSwapped : thinData.readUInt32(at: offset)
            let cmdsize = swap ? thinData.readUInt32(at: offset + 4).byteSwapped : thinData.readUInt32(at: offset + 4)
            
            if cmd == Self.LC_SEGMENT {
                guard offset + 32 <= thinData.count else { break }
                let nameData = thinData.subdata(in: offset + 8..<offset + 24)
                let name = String(data: nameData.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "unknown"
                let vmaddr = swap ? thinData.readUInt32(at: offset + 24).byteSwapped : thinData.readUInt32(at: offset + 24)
                let vmsize = swap ? thinData.readUInt32(at: offset + 28).byteSwapped : thinData.readUInt32(at: offset + 28)
                list.append((name: name, offset: UInt64(vmaddr), size: UInt64(vmsize)))
            } else if cmd == Self.LC_SEGMENT_64 {
                guard offset + 40 <= thinData.count else { break }
                let nameData = thinData.subdata(in: offset + 8..<offset + 24)
                let name = String(data: nameData.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "unknown"
                let vmaddr = swap ? thinData.readUInt64(at: offset + 24).byteSwapped : thinData.readUInt64(at: offset + 24)
                let vmsize = swap ? thinData.readUInt64(at: offset + 32).byteSwapped : thinData.readUInt64(at: offset + 32)
                list.append((name: name, offset: vmaddr, size: vmsize))
            }
            offset += Int(cmdsize)
        }
        return list
    }

    // MARK: - Private Inner Helpers

    private func extractRawBlob(slotType: UInt32) throws -> Data {
        let thinData = try getThinBinaryData()
        guard thinData.count >= 28 else { throw MachOParserError.invalidMachO }
        let magic = thinData.readUInt32(at: 0)
        guard magic == Self.MH_MAGIC || magic == Self.MH_CIGAM || magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64 else {
            throw MachOParserError.invalidMachO
        }
        
        let swap = (magic == Self.MH_CIGAM || magic == Self.MH_CIGAM_64)
        let is64 = (magic == Self.MH_MAGIC_64 || magic == Self.MH_CIGAM_64)
        
        let ncmds = swap ? thinData.readUInt32(at: 16).byteSwapped : thinData.readUInt32(at: 16)
        let headerSize = is64 ? 32 : 28
        
        var offset = headerSize
        for _ in 0..<Int(ncmds) {
            guard offset + 8 <= thinData.count else { throw MachOParserError.invalidMachO }
            let cmd = swap ? thinData.readUInt32(at: offset).byteSwapped : thinData.readUInt32(at: offset)
            let cmdsize = swap ? thinData.readUInt32(at: offset + 4).byteSwapped : thinData.readUInt32(at: offset + 4)
            
            if cmd == Self.LC_CODE_SIGNATURE {
                guard offset + 16 <= thinData.count else { throw MachOParserError.invalidMachO }
                let dataoff = swap ? thinData.readUInt32(at: offset + 8).byteSwapped : thinData.readUInt32(at: offset + 8)
                let datasize = swap ? thinData.readUInt32(at: offset + 12).byteSwapped : thinData.readUInt32(at: offset + 12)
                
                guard Int(dataoff) + Int(datasize) <= thinData.count else { throw MachOParserError.invalidMachO }
                let sigData = thinData.subdata(in: Int(dataoff)..<Int(dataoff + datasize))
                return try parseRawSignatureBlob(sigData, slotType: slotType)
            }
            offset += Int(cmdsize)
        }
        throw MachOParserError.missingSignature
    }

    private func parseRawSignatureBlob(_ data: Data, slotType: UInt32) throws -> Data {
        guard data.count >= 12 else { throw MachOParserError.invalidMachO }
        let magic = data.readUInt32BigEndian(at: 0)
        guard magic == Self.SUPERBLOB_MAGIC else { throw MachOParserError.invalidMachO }
        
        let count = data.readUInt32BigEndian(at: 8)
        for i in 0..<Int(count) {
            let offset = 12 + i * 8
            guard offset + 8 <= data.count else { throw MachOParserError.invalidMachO }
            let type = data.readUInt32BigEndian(at: offset)
            let blobOffset = data.readUInt32BigEndian(at: offset + 4)
            
            if type == slotType {
                let absOffset = Int(blobOffset)
                guard absOffset + 8 <= data.count else { throw MachOParserError.invalidMachO }
                let length = data.readUInt32BigEndian(at: absOffset + 4)
                
                guard absOffset + Int(length) <= data.count else { throw MachOParserError.invalidMachO }
                return data.subdata(in: absOffset..<absOffset + Int(length))
            }
        }
        throw MachOParserError.missingSignature
    }
}

// MARK: - ASN1Decoder

fileprivate struct ASN1Decoder {
    static func findCertificates(in data: Data) -> [Data] {
        var results = [Data]()
        
        func parseTLV(offset: inout Int, limit: Int) {
            guard offset + 2 <= limit else { return }
            let tag = data[offset]
            let lengthByte = data[offset + 1]
            offset += 2
            
            var length = Int(lengthByte)
            if lengthByte & 0x80 != 0 {
                let numBytes = Int(lengthByte & 0x7F)
                guard offset + numBytes <= limit else { return }
                var val = 0
                for i in 0..<numBytes {
                    val = (val << 8) | Int(data[offset + i])
                }
                offset += numBytes
                length = val
            }
            
            guard offset + length <= limit else { return }
            
            if tag == 0x30 {
                let start = offset
                var subOffset = offset
                parseTLV(offset: &subOffset, limit: start + length)
                offset += length
            } else if tag == 0xA0 { // Context-specific [0] (certificates field)
                var subOffset = offset
                let subLimit = offset + length
                while subOffset < subLimit {
                    let certStart = subOffset
                    var tempOffset = subOffset
                    guard tempOffset + 2 <= subLimit else { break }
                    let cTag = data[tempOffset]
                    let cLenByte = data[tempOffset + 1]
                    tempOffset += 2
                    var cLen = Int(cLenByte)
                    if cLenByte & 0x80 != 0 {
                        let num = Int(cLenByte & 0x7F)
                        guard tempOffset + num <= subLimit else { break }
                        var v = 0
                        for i in 0..<num {
                            v = (v << 8) | Int(data[tempOffset + i])
                        }
                        tempOffset += num
                        cLen = v
                    }
                    guard tempOffset + cLen <= subLimit else { break }
                    let certData = data.subdata(in: certStart..<tempOffset + cLen)
                    if cTag == 0x30 {
                        results.append(certData)
                    }
                    subOffset = tempOffset + cLen
                }
                offset += length
            } else {
                offset += length
            }
        }
        
        var offset = 0
        while offset < data.count {
            let start = offset
            parseTLV(offset: &offset, limit: data.count)
            if offset == start {
                break
            }
        }
        return results
    }
}

// MARK: - Data Extensions

fileprivate extension Data {
    func readUInt32(at offset: Int) -> UInt32 {
        guard offset + 4 <= self.count else { return 0 }
        return self.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
    }
    
    // Read at offset a 64 bit UInt
    func readUInt64(at offset: Int) -> UInt64 {
        guard offset + 8 <= self.count else { return 0 }
        return self.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self) }
    }
    
    // Read at offset a 32 bit UInt and convert it to host type (bigEndian)
    func readUInt32BigEndian(at offset: Int) -> UInt32 {
        return UInt32(bigEndian: readUInt32(at: offset))
    }

    func readUInt64BigEndian(at offset: Int) -> UInt64 {
        return UInt64(bigEndian: readUInt64(at: offset))
    }
}
