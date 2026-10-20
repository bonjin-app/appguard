import Foundation
import CryptoKit
import Darwin

/// Fixed, deliberately small heuristic sets. No images are enumerated and no suspicious code is loaded or invoked.
struct LocalRiskDeviceProbes {
    let artifact: (String) -> LocalRiskObservation
    let symbol: (String) -> LocalRiskObservation
    let environment: (String) -> LocalRiskObservation

    func rootArtifacts() -> [LocalRiskObservation] {
        ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/bin/bash",
         "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt", "/var/jb"].map(artifact)
    }
    func hookArtifacts() -> [LocalRiskObservation] {
        ["MSHookFunction", "MSHookMessageEx", "frida_agent_main", "frida_agent_main_full"].map(symbol) +
        ["DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"].map(environment)
    }
}

struct LocalRiskNativeProbe: LocalRiskProbe {
    let bundle: Bundle
    private let readBytes: (Int32, UnsafeMutableRawPointer?, Int) -> Int
    init(bundle: Bundle = .main, readBytes: @escaping (Int32, UnsafeMutableRawPointer?, Int) -> Int = { Darwin.read($0, $1, $2) }) {
        self.bundle = bundle; self.readBytes = readBytes
    }

    func debuggerAttached() throws -> LocalRiskObservation {
        // QA1361 restricts kinfo_proc to debug builds (API_UNSTABLE). Release/macOS are explicitly unknown.
        #if DEBUG && os(iOS)
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        guard result == 0, size == MemoryLayout<kinfo_proc>.size else { return .unavailable }
        return info.kp_proc.p_flag & P_TRACED != 0 ? .present : .absent
        #else
        return .unavailable
        #endif
    }

    func rootArtifacts() throws -> [LocalRiskObservation] {
        #if os(iOS) && !targetEnvironment(simulator)
        return device.rootArtifacts()
        #else
        return [.unavailable]
        #endif
    }
    func hookArtifacts() throws -> [LocalRiskObservation] {
        #if os(iOS) && !targetEnvironment(simulator)
        return device.hookArtifacts()
        #else
        return [.unavailable]
        #endif
    }

    #if os(iOS) && !targetEnvironment(simulator)
    private var device: LocalRiskDeviceProbes {
        LocalRiskDeviceProbes(artifact: { path in
            // Existence only: do not access timestamps/metadata outside the app container.
            let result = path.withCString { access($0, F_OK) }
            return Self.fileObservation(result: result, error: errno)
        }, symbol: { symbol in
            let address = symbol.withCString { dlsym(UnsafeMutableRawPointer(bitPattern: -2), $0) }
            return address == nil ? .absent : .present
        }, environment: { name in
            name.withCString { Self.environmentObservation(getenv($0)) }
        })
    }
    #endif

    static func fileObservation(result: Int32, error: Int32) -> LocalRiskObservation {
        if result == 0 { return .present }
        return error == ENOENT || error == ENOTDIR ? .absent : .unavailable
    }

    static func environmentObservation(_ value: UnsafePointer<CChar>?) -> LocalRiskObservation {
        guard let value else { return .absent }
        let length = strnlen(value, 4097)
        guard length <= 4096 else { return .unavailable }
        return length == 0 ? .absent : .present
    }

    func appIdentifier() throws -> String? {
        guard let identifier = bundle.bundleIdentifier, (1...255).contains(identifier.utf8.count) else { return nil }
        return identifier
    }

    func resourceObservations(_ pins: [String: String]) throws -> [LocalRiskObservation] {
        // max8 pins x max1MiB means no more than 8MiB can be streamed per scan.
        guard let root = Self.resolve(bundle.bundleURL.path) else { return [.unavailable] }
        return pins.keys.sorted().map { path in
            resource(path: root + "/" + path, expectedHash: pins[path]!, root: root)
        }
    }

    private static func resolve(_ path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard path.withCString({ realpath($0, &buffer) }) != nil else { return nil }
        return String(cString: buffer)
    }

    private func resource(path: String, expectedHash: String, root: String) -> LocalRiskObservation {
        guard let resolved = Self.resolve(path) else {
            let error = errno
            return error == ENOENT || error == ENOTDIR ? .present : .unavailable
        }
        guard Self.inside(resolved, root: root) else { return .unavailable }
        let descriptor = resolved.withCString { open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) }
        guard descriptor >= 0 else {
            let error = errno
            return error == ENOENT || error == ENOTDIR ? .present : .unavailable
        }
        defer { close(descriptor) }
        // Validate the actual opened descriptor before reading, catching ancestor symlink swaps before open.
        var descriptorPath = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard fcntl(descriptor, F_GETPATH, &descriptorPath) == 0,
              Self.inside(String(cString: descriptorPath), root: root) else { return .unavailable }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_size >= 0, metadata.st_size <= 1_048_576 else { return .unavailable }
        let initialSize = metadata.st_size
        var hash = SHA256()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        var total = 0
        while total < 1_048_576 {
            let maximum = min(buffer.count, 1_048_576 - total)
            let count = buffer.withUnsafeMutableBytes { readBytes(descriptor, $0.baseAddress, maximum) }
            if count < 0 { return .unavailable }
            if count == 0 { break }
            total += count
            hash.update(data: Data(buffer.prefix(count)))
        }
        // No extra byte is read past the bound. A growing/truncated file is unknown, never a partial digest match.
        guard fstat(descriptor, &metadata) == 0, metadata.st_size == initialSize, metadata.st_size == total else { return .unavailable }
        let digest = hash.finalize().map { String(format: "%02x", $0) }.joined()
        return digest == expectedHash ? .absent : .present
    }

    private static func inside(_ path: String, root: String) -> Bool { path.hasPrefix(root + "/") }
}
