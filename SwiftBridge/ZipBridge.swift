//
//  ZipBridge.swift
//  AltSign
//

import Foundation
import NativeBridge

public enum ZipBridge {

    // MARK: - Archive Reader

    public final class Archive {

        private let handle: native_bridge_unzFile

        private init(_ handle: native_bridge_unzFile) {
            self.handle = handle
        }

        deinit {
            native_bridge_unzClose(handle)
        }

        // MARK: Open

        public static func open(at url: URL) throws -> Archive {
            verboseLog("[AltSign] ZipBridge.Archive.open(at: \(url.path)) started")
            guard let h = url.path.withCString({
                native_bridge_unzOpen($0)
            }) else {
                debugLog("[AltSign] ZipBridge.Archive.open failed: corrupt archive or unable to open")
                throw ZipError.corruptArchive(url)
            }
            verboseLog("[AltSign] ZipBridge.Archive.open succeeded")
            return Archive(h)
        }

        // MARK: Navigation

        public func goToFirstFile() throws {
            verboseLog("[AltSign] ZipBridge.Archive.goToFirstFile called")
            guard native_bridge_unzGoToFirstFile(handle) == 0 else {
                debugLog("[AltSign] ZipBridge.Archive.goToFirstFile failed")
                throw ZipError.readFailed(.init(fileURLWithPath: ""))
            }
        }

        public func goToNextFile() -> Bool {
            let hasNext = native_bridge_unzGoToNextFile(handle) == 0
            verboseLog("[AltSign] ZipBridge.Archive.goToNextFile called. Has next file: \(hasNext)")
            return hasNext
        }

        // MARK: File Info

        public func currentFilename() throws -> String {
            var info = [UInt8](repeating: 0, count: 256)
            var name = [CChar](repeating: 0, count: 1024)

            let r = native_bridge_unzGetCurrentFileInfo(
                handle,
                &info,
                &name,
                1024
            )

            guard r == 0 else {
                debugLog("[AltSign] ZipBridge.Archive.currentFilename failed to get info from native bridge")
                throw ZipError.readFailed(.init(fileURLWithPath: ""))
            }

            let filename = String(cString: name)
            verboseLog("[AltSign] ZipBridge.Archive.currentFilename retrieved: \(filename)")
            return filename
        }

        public func currentFileExternalAttributes() -> UInt32 {
            return native_bridge_unzGetCurrentFileExternalAttributes(handle)
        }

        // MARK: Reading

        public func readCurrentFile() throws -> Data {
            verboseLog("[AltSign] ZipBridge.Archive.readCurrentFile started")
            guard native_bridge_unzOpenCurrentFile(handle) == 0 else {
                debugLog("[AltSign] ZipBridge.Archive.readCurrentFile failed: native_bridge_unzOpenCurrentFile returned error")
                throw ZipError.readFailed(.init(fileURLWithPath: ""))
            }

            defer {
                native_bridge_unzCloseCurrentFile(handle)
            }

            var result = Data()
            var buffer = [UInt8](repeating: 0, count: 32_768)

            while true {

                let read = native_bridge_unzReadCurrentFile(
                    handle,
                    &buffer,
                    UInt32(buffer.count)
                )

                if read < 0 {
                    debugLog("[AltSign] ZipBridge.Archive.readCurrentFile failed: native_bridge_unzReadCurrentFile returned error code \(read)")
                    throw ZipError.readFailed(.init(fileURLWithPath: ""))
                }

                if read == 0 { break }

                result.append(buffer, count: Int(read))
            }

            verboseLog("[AltSign] ZipBridge.Archive.readCurrentFile completed. Read size: \(result.count) bytes")
            return result
        }
    }

    // MARK: - Archive Writer

    public final class Writer {

        private let handle: native_bridge_zipFile

        private init(_ handle: native_bridge_zipFile) {
            self.handle = handle
        }

        deinit {
            verboseLog("[AltSign] ZipBridge.Writer.deinit closing zip handle")
            native_bridge_zipClose(handle)
        }

        public static func create(at url: URL) throws -> Writer {
            verboseLog("[AltSign] ZipBridge.Writer.create(at: \(url.path)) started")
            guard let h = url.path.withCString({
                native_bridge_zipOpen($0)
            }) else {
                debugLog("[AltSign] ZipBridge.Writer.create failed: unable to create/open zip file")
                throw ZipError.writeFailed(url)
            }
            verboseLog("[AltSign] ZipBridge.Writer.create succeeded")
            return Writer(h)
        }

        public func writeFile(path: String, data: Data?, permissions: UInt32) throws {
            verboseLog("[AltSign] ZipBridge.Writer.writeFile started for internal path: '\(path)', data size: \(data?.count ?? 0) bytes, permissions: \(String(format: "%0o", permissions))")

            let openOK = path.withCString {
                native_bridge_zipOpenNewFileInZipWithPermissions(handle, $0, permissions)
            } == 0

            guard openOK else {
                debugLog("[AltSign] ZipBridge.Writer.writeFile failed: native_bridge_zipOpenNewFileInZipWithPermissions returned error")
                throw ZipError.writeFailed(.init(fileURLWithPath: path))
            }

            defer {
                native_bridge_zipCloseFileInZip(handle)
            }

            guard let data else {
                verboseLog("[AltSign] ZipBridge.Writer.writeFile completed: no data to write")
                return
            }

            let ok = data.withUnsafeBytes {
                native_bridge_zipWriteInFileInZip(
                    handle,
                    $0.baseAddress,
                    UInt32(data.count)
                )
            } == 0

            guard ok else {
                debugLog("[AltSign] ZipBridge.Writer.writeFile failed: native_bridge_zipWriteInFileInZip returned error")
                throw ZipError.writeFailed(.init(fileURLWithPath: path))
            }

            verboseLog("[AltSign] ZipBridge.Writer.writeFile completed successfully")
        }
    }
}

public enum ZipError: Error {

    case fileNotFound(URL)
    case corruptArchive(URL)
    case readFailed(URL)
    case writeFailed(URL)
    case missingAppBundle(URL)
}

// MARK: - LocalizedError

extension ZipError: LocalizedError {

    public var errorDescription: String? {
        switch self {

        case .fileNotFound(let url):
            return "File not found: \(url.lastPathComponent)"

        case .corruptArchive(let url):
            return "Archive appears to be corrupt: \(url.lastPathComponent)"

        case .readFailed(let url):
            return "Failed to read archive: \(url.lastPathComponent)"

        case .writeFailed(let url):
            return "Failed to write archive: \(url.lastPathComponent)"

        case .missingAppBundle(let url):
            return "No .app bundle found inside \(url.lastPathComponent)"
        }
    }
}
