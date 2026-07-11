//
//  FileManager+Zip.swift
//  AltSign
//

import Foundation
import SwiftBridge

extension FileManager {

    // MARK: - Zip POSIX Constants
    // POSIX file type flags (external attributes in ZIP catalog are shifted by 16 bits)
    private static let S_IFREG: UInt32 = 0o100000 // Regular file
    private static let S_IFDIR: UInt32 = 0o040000 // Directory

    // Default permissions when not defined in the source archive
    private static let defaultFilePermissions: UInt32 = 0o644
    private static let defaultDirPermissions: UInt32 = 0o755

    // MARK: unzipArchive

    func unzipArchive(
        at archiveURL: URL,
        to directoryURL: URL,
        progress: Progress? = nil
    ) throws {
        verboseLog("[AltSign] FileManager.unzipArchive started for archive: \(archiveURL.path) to: \(directoryURL.path)")
        let archive = try ZipBridge.Archive.open(at: archiveURL)
        try archive.goToFirstFile()

        repeat {

            let name = try archive.currentFilename()

            if name.hasPrefix("__MACOSX") {
                verboseLog("[AltSign] FileManager.unzipArchive: skipping __MACOSX entry: \(name)")
                continue
            }

            let outputURL =
                directoryURL.appendingPathComponent(name)

            let externalAttributes = archive.currentFileExternalAttributes()
            var permissions = (externalAttributes >> 16) & 0x01FF
            if permissions == 0 {
                permissions = name.hasSuffix("/") ? Self.defaultDirPermissions : Self.defaultFilePermissions
            }

            if name.hasSuffix("/") {
                verboseLog("[AltSign] FileManager.unzipArchive: creating directory: \(outputURL.path)")
                try createDirectory(
                    at: outputURL,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: NSNumber(value: permissions)]
                )
                continue
            }

            verboseLog("[AltSign] FileManager.unzipArchive: extracting file: \(outputURL.path)")
            try createDirectory(
                at: outputURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )

            let data = try archive.readCurrentFile()

            createFile(
                atPath: outputURL.path,
                contents: data,
                attributes: [.posixPermissions: NSNumber(value: permissions)]
            )

            progress?.completedUnitCount += Int64(data.count)

        } while archive.goToNextFile()
        verboseLog("[AltSign] FileManager.unzipArchive completed successfully")
    }

    public func unzipAppBundle(
        at ipaURL: URL,
        to directoryURL: URL
    ) throws -> URL {
        verboseLog("[AltSign] FileManager.unzipAppBundle starting for: \(ipaURL.path) to: \(directoryURL.path)")
        try unzipArchive(at: ipaURL, to: directoryURL)

        let payload = directoryURL.appendingPathComponent("Payload")
        let contents = try contentsOfDirectory(atPath: payload.path)
        verboseLog("[AltSign] FileManager.unzipAppBundle: checking payload folder contents: \(contents)")

        for file in contents where file.lowercased().hasSuffix(".app") {

            let appURL = payload.appendingPathComponent(file)
            let outputURL = directoryURL.appendingPathComponent(file)

            verboseLog("[AltSign] FileManager.unzipAppBundle: moving app bundle from \(appURL.path) to \(outputURL.path)")
            try moveItem(at: appURL, to: outputURL)
            try removeItem(at: payload)

            verboseLog("[AltSign] FileManager.unzipAppBundle completed. Return app path: \(outputURL.path)")
            return outputURL
        }

        verboseLog("[AltSign] FileManager.unzipAppBundle error: missing app bundle inside Payload folder of \(ipaURL.path)")
        throw ZipError.missingAppBundle(ipaURL)
    }

    public func unzipAppBundle(at ipaURL: URL, toDirectory directoryURL: URL) throws -> URL {
        return try self.unzipAppBundle(at: ipaURL, to: directoryURL)
    }

    // MARK: zipAppBundle

    public func zipAppBundle(at appBundleURL: URL) throws -> URL {
        verboseLog("[AltSign] FileManager.zipAppBundle starting for: \(appBundleURL.path)")
        let name = appBundleURL.deletingPathExtension().lastPathComponent

        let ipaURL = appBundleURL
            .deletingLastPathComponent()
            .appendingPathComponent("\(name).ipa")

        if fileExists(atPath: ipaURL.path) {
            verboseLog("[AltSign] FileManager.zipAppBundle: removing existing ipa at \(ipaURL.path)")
            try removeItem(at: ipaURL)
        }

        let writer = try ZipBridge.Writer.create(at: ipaURL)

        let payloadRoot =
            URL(fileURLWithPath: "Payload", isDirectory: true)

        let bundleRoot =
            payloadRoot.appendingPathComponent(
                appBundleURL.lastPathComponent
            )

        let enumerator = self.enumerator(
            at: appBundleURL,
            includingPropertiesForKeys: [.isDirectoryKey]
        )!

        verboseLog("[AltSign] FileManager.zipAppBundle: enumerating contents of app bundle...")
        for case let fileURL as URL in enumerator {

            var isDir: ObjCBool = false
            fileExists(atPath: fileURL.path, isDirectory: &isDir)

            let relative = fileURL.path
                .replacingOccurrences(of: appBundleURL.path + "/", with: "")

            let zipPath =
                bundleRoot.appendingPathComponent(relative).path +
                (isDir.boolValue ? "/" : "")

            let attributes = try self.attributesOfItem(atPath: fileURL.path)
            let posixPermissions = (attributes[.posixPermissions] as? NSNumber)?.uint32Value ?? (isDir.boolValue ? Self.defaultDirPermissions : Self.defaultFilePermissions)
            let fileType = isDir.boolValue ? Self.S_IFDIR : Self.S_IFREG
            let permissions = fileType + posixPermissions

            verboseLog("[AltSign] FileManager.zipAppBundle: writing zip entry relative: \(relative), path in zip: \(zipPath), isDir: \(isDir.boolValue), permissions: \(String(format: "%0o", permissions))")
            let data = isDir.boolValue ? nil : try Data(contentsOf: fileURL)

            try writer.writeFile(path: zipPath, data: data, permissions: permissions)
        }

        verboseLog("[AltSign] FileManager.zipAppBundle completed. Packaged ipa path: \(ipaURL.path)")
        return ipaURL
    }
}
