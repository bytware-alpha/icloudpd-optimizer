import AppKit
import Combine
import Foundation
import Darwin
import SwiftUI

private let dashboardLogTailBytes: UInt64 = 650_000
private let dashboardLogRefreshInterval: TimeInterval = 5
private let dashboardQueueReportRefreshInterval: TimeInterval = 20
private let workerActivityFreshWindow: TimeInterval = 300
private let dashboardMinimumWindowSize = NSSize(width: 1080, height: 760)

struct PrimeStatus: Encodable {
    let ok: Bool
    let configPath: String
    let readRoots: [String]
    let writeCanaryDir: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case ok
        case configPath = "config_path"
        case readRoots = "read_roots"
        case writeCanaryDir = "write_canary_dir"
        case error
    }
}

struct MonitorAccessPlan {
    let configPath: String
    let readRoots: [String]
    let writeCanaryDir: String?
    let suggestedRoot: String?
}

struct NASAuthorization {
    let plan: MonitorAccessPlan
    let scopedAccess: [URL]

    func stopAccessingSecurityScopedResources() {
        for url in scopedAccess {
            url.stopAccessingSecurityScopedResource()
        }
    }
}

struct StoredBookmarks: Codable {
    let version: Int
    let bookmarks: [Data]
}

struct MonitorStatsEnvelope: Decodable {
    let stats: MonitorStatsPayload
    let verifiedMetrics: VerifiedMetricsPayload?

    enum CodingKeys: String, CodingKey {
        case stats
        case verifiedMetrics = "verified_metrics"
    }
}

struct MonitorStatsPayload: Decodable {
    let scansStarted: Int
    let scansCompleted: Int
    let conversionsAttempted: Int
    let conversionsCompleted: Int
    let heicsVerified: Int
    let originalsResolved: Int
    let uploadsCompleted: Int
    let originalsDeleted: Int
    let uploadedHeicBytes: Int64
    let deletedRawBytes: Int64
    let bytesSaved: Int64
    let failures: Int
    let lastError: String?
    let stateCounts: [String: Int]
    var terminalRecords: Int? = nil
    var noActionRecords: Int? = nil
    var needsReviewRecords: Int? = nil
    var failedRecords: Int? = nil
    var pendingRecords: Int? = nil

    enum CodingKeys: String, CodingKey {
        case scansStarted = "scans_started"
        case scansCompleted = "scans_completed"
        case conversionsAttempted = "conversions_attempted"
        case conversionsCompleted = "conversions_completed"
        case heicsVerified = "heics_verified"
        case originalsResolved = "originals_resolved"
        case uploadsCompleted = "uploads_completed"
        case originalsDeleted = "originals_deleted"
        case uploadedHeicBytes = "uploaded_heic_bytes"
        case deletedRawBytes = "deleted_raw_bytes"
        case bytesSaved = "bytes_saved"
        case failures
        case lastError = "last_error"
        case stateCounts = "state_counts"
        case terminalRecords = "terminal_records"
        case noActionRecords = "no_action_records"
        case needsReviewRecords = "needs_review_records"
        case failedRecords = "failed_records"
        case pendingRecords = "pending_records"
    }
}

struct DashboardMonitorConfig: Decodable {
    let statsPath: String?
    let rollingWorkerCount: Int?

    enum CodingKeys: String, CodingKey {
        case statsPath = "stats_path"
        case rollingWorkerCount = "rolling_worker_count"
    }
}

struct VerifiedMetricsPayload: Decodable {
    let totalRecords: Int
    let stateCounts: [String: Int]
    let uploadedReplacements: Int
    let uploadedHeicBytes: Int64
    let uploadedSizeMetricsComplete: Bool
    let uploadedRecordsMissingSizeProofs: Int
    let deletedOriginals: Int
    let deletedRawBytes: Int64
    let verifiedBytesSaved: Int64
    let deletedSizeMetricsComplete: Bool
    let deletedRecordsMissingSizeProofs: Int
    var terminalRecords: Int? = nil
    var noActionRecords: Int? = nil
    var needsReviewRecords: Int? = nil
    var failedRecords: Int? = nil
    var pendingRecords: Int? = nil

    enum CodingKeys: String, CodingKey {
        case totalRecords = "total_records"
        case stateCounts = "state_counts"
        case uploadedReplacements = "uploaded_replacements"
        case uploadedHeicBytes = "uploaded_heic_bytes"
        case uploadedSizeMetricsComplete = "uploaded_size_metrics_complete"
        case uploadedRecordsMissingSizeProofs = "uploaded_records_missing_size_proofs"
        case deletedOriginals = "deleted_originals"
        case deletedRawBytes = "deleted_raw_bytes"
        case verifiedBytesSaved = "verified_bytes_saved"
        case deletedSizeMetricsComplete = "deleted_size_metrics_complete"
        case deletedRecordsMissingSizeProofs = "deleted_records_missing_size_proofs"
        case terminalRecords = "terminal_records"
        case noActionRecords = "no_action_records"
        case needsReviewRecords = "needs_review_records"
        case failedRecords = "failed_records"
        case pendingRecords = "pending_records"
    }
}

struct ScanSummary: Decodable {
    let rawFilesSeen: Int
    let candidatesVerified: Int
    let conversionsAttempted: Int
    let conversionsCompleted: Int
    let heicsVerified: Int
    let originalsResolved: Int
    let uploadsCompleted: Int
    let originalsDeleted: Int
    let bytesSaved: Int64
    let failures: Int
    let startedUnixSeconds: TimeInterval
    let finishedUnixSeconds: TimeInterval
    let lastError: String?

    enum CodingKeys: String, CodingKey {
        case rawFilesSeen = "raw_files_seen"
        case candidatesVerified = "candidates_verified"
        case conversionsAttempted = "conversions_attempted"
        case conversionsCompleted = "conversions_completed"
        case heicsVerified = "heics_verified"
        case originalsResolved = "originals_resolved"
        case uploadsCompleted = "uploads_completed"
        case originalsDeleted = "originals_deleted"
        case bytesSaved = "bytes_saved"
        case failures
        case startedUnixSeconds = "started_unix_seconds"
        case finishedUnixSeconds = "finished_unix_seconds"
        case lastError = "last_error"
    }

    var durationSeconds: TimeInterval {
        max(0, finishedUnixSeconds - startedUnixSeconds)
    }
}

struct MonitorQueuePayload: Decodable {
    let configuredMode: String
    let rollingLifecycle: Bool
    let jobs: Int
    let rollingWorkerCount: Int?
    let cpuStageSlots: Int?
    let convertStageSlots: Int?
    let maxLifecyclePerScan: Int
    let maxConversionsPerScan: Int
    let stateCounts: [String: Int]
    let queueCounts: [String: Int]
    let failureCounts: [String: Int]
    let verifiedMetrics: VerifiedMetricsPayload
    let activeLifecycle: [QueueAssetPayload]
    let workerSlots: [QueueWorkerSlotPayload]

    enum CodingKeys: String, CodingKey {
        case configuredMode = "configured_mode"
        case rollingLifecycle = "rolling_lifecycle"
        case jobs
        case rollingWorkerCount = "rolling_worker_count"
        case cpuStageSlots = "cpu_stage_slots"
        case convertStageSlots = "convert_stage_slots"
        case maxLifecyclePerScan = "max_lifecycle_per_scan"
        case maxConversionsPerScan = "max_conversions_per_scan"
        case stateCounts = "state_counts"
        case queueCounts = "queue_counts"
        case failureCounts = "failure_counts"
        case verifiedMetrics = "verified_metrics"
        case activeLifecycle = "active_lifecycle"
        case workerSlots = "worker_slots"
    }
}

struct QueueAssetPayload: Decodable, Identifiable {
    let assetId: String
    let state: String
    let nextStage: String
    let rawSizeBytes: Int64

    var id: String { assetId }

    enum CodingKeys: String, CodingKey {
        case assetId = "asset_id"
        case state
        case nextStage = "next_stage"
        case rawSizeBytes = "raw_size_bytes"
    }
}

struct QueueWorkerSlotPayload: Decodable, Identifiable {
    let workerId: Int
    let firstAssetId: String
    let nextStage: String
    let stages: [String]

    var id: Int { workerId }

    enum CodingKeys: String, CodingKey {
        case workerId = "worker_id"
        case firstAssetId = "first_asset_id"
        case nextStage = "next_stage"
        case stages
    }
}

struct WorkerActivity: Identifiable {
    let workerId: Int
    let assetId: String?
    let stage: String
    let detail: String
    let updatedAt: Date?
    let finished: Bool

    var id: Int { workerId }
}

enum DashboardEventTone {
    case active
    case success
    case warning
    case blocked
    case neutral
}

struct DashboardLogEvent: Identifiable {
    let timestamp: Date?
    let event: String
    let title: String
    let detail: String
    let tone: DashboardEventTone

    var id: String {
        let seconds = timestamp?.timeIntervalSince1970 ?? 0
        return "\(seconds)|\(event)|\(title)|\(detail)"
    }
}

struct ServiceSnapshot {
    let running: Bool
    let nativeApp: Bool
    let pid: String?
    let program: String?
    let raw: String
}

struct DashboardLogState {
    let raw: String
    let events: [DashboardLogEvent]
    let workerActivities: [Int: WorkerActivity]
    let throughput: LiveThroughputMetrics
}

struct LiveThroughputMetrics {
    let uploads5m: Int
    let uploads15m: Int
    let deletes15m: Int
    let conversions15m: Int
    let blockedAssets15m: Int
    let failureAttempts15m: Int
    let assetlessFailureAttempts15m: Int
    let bytesSaved15m: Int64
    let windowSeconds: TimeInterval
    let coveredSeconds: TimeInterval

    static let empty = LiveThroughputMetrics(
        uploads5m: 0,
        uploads15m: 0,
        deletes15m: 0,
        conversions15m: 0,
        blockedAssets15m: 0,
        failureAttempts15m: 0,
        assetlessFailureAttempts15m: 0,
        bytesSaved15m: 0,
        windowSeconds: 900,
        coveredSeconds: 0
    )

    func hourlyRate(_ count: Int) -> String {
        let measuredSeconds = coveredSeconds > 0 ? min(windowSeconds, coveredSeconds) : windowSeconds
        return DashboardFormat.rate(count, over: measuredSeconds)
    }

    func coverageDetail() -> String {
        if coveredSeconds >= windowSeconds - 5 {
            return "last 15m"
        }
        if coveredSeconds > 0 {
            return "last \(DashboardFormat.duration(coveredSeconds)) captured"
        }
        return "waiting for live events"
    }
}

struct WorkerLaneSnapshot: Identifiable {
    let workerId: Int
    let firstAssetId: String?
    let nextStage: String?

    var id: Int { workerId }
}

struct ThroughputStat: Identifiable {
    let id: String
    let label: String
    let value: String
    let detail: String
    let tone: DashboardEventTone
}

private let workerLifecycleStages = [
    "resolve_original_assets",
    "convert_heic",
    "verify_converted_heics",
    "upload_verified_heics",
    "record_local_mirrors",
]

struct PipelineStageDefinition: Identifiable {
    let key: String
    let title: String
    let detail: String

    var id: String { key }
}

private let pipelineStages = [
    PipelineStageDefinition(key: "resolve_original_assets", title: "Match RAW", detail: "Find the exact iCloud original"),
    PipelineStageDefinition(key: "convert_heic", title: "Convert", detail: "Encode the HEIC replacement"),
    PipelineStageDefinition(key: "verify_converted_heics", title: "Quality check", detail: "Compare preview, metadata, pixels"),
    PipelineStageDefinition(key: "upload_verified_heics", title: "Upload HEIC", detail: "Send replacement to Photos"),
    PipelineStageDefinition(key: "record_local_mirrors", title: "NAS proof", detail: "Confirm the RAW is backed up"),
    PipelineStageDefinition(key: "delete_original_assets", title: "Safe delete", detail: "Delete only after all proofs"),
]

struct DashboardMetricsParser {
    static func liveThroughputMetrics(_ text: String, now: TimeInterval = Date().timeIntervalSince1970) -> LiveThroughputMetrics {
        let window15m: TimeInterval = 15 * 60
        let window5m: TimeInterval = 5 * 60
        let parsedEvents = metricEvents(text, now: now)
        let coveredSeconds = min(window15m, parsedEvents.map(\.age).max() ?? 0)
        let events = parsedEvents.filter { $0.age <= window15m }
        var uploads5m = 0
        var uploads15m = 0
        var deletes15m = 0
        var conversions15m = 0
        var blockedAssetIds = Set<String>()
        var seenFailureIds = Set<String>()
        var failureAttempts15m = 0
        var assetlessFailureAttempts15m = 0
        var bytesSaved15m: Int64 = 0

        func recordAssetFailure(_ assetId: String) {
            failureAttempts15m += 1
            blockedAssetIds.insert(assetId)
        }

        func recordFailure(_ fields: [String: Any]) {
            if let failureId = fields["failure_id"] as? String,
               !failureId.isEmpty,
               !seenFailureIds.insert(failureId).inserted
            {
                return
            }
            if let assetId = fields["asset_id"] as? String, !assetId.isEmpty {
                recordAssetFailure(assetId)
            } else {
                failureAttempts15m += 1
                assetlessFailureAttempts15m += 1
            }
        }

        for metricEvent in events {
            let fields = metricEvent.fields
            switch metricEvent.name {
            case "delete_batch_finished":
                deletes15m += Int(int64Field("recorded_deletes", fields: fields) ?? 0)
                bytesSaved15m += int64Field("bytes_saved", fields: fields) ?? 0
            case "upload_finished":
                if boolField("uploaded", fields: fields) {
                    uploads15m += 1
                    if metricEvent.age <= window5m {
                        uploads5m += 1
                    }
                } else {
                    recordFailure(fields)
                }
            case "conversion_finished":
                if boolField("converted", fields: fields) {
                    conversions15m += 1
                } else {
                    recordFailure(fields)
                }
            case "heic_verify_finished":
                if !boolField("verified", fields: fields) {
                    recordFailure(fields)
                }
            case "original_asset_resolve_batch_finished":
                let unresolvedAssetIds = stringArrayField("unresolved_asset_ids", fields: fields)
                if unresolvedAssetIds.isEmpty {
                    if fields["error"] != nil {
                        recordFailure(fields)
                    }
                } else {
                    unresolvedAssetIds.forEach(recordAssetFailure)
                }
            case "monitor_failed":
                recordFailure(fields)
            default:
                if fields["error"] != nil && metricEvent.name.hasSuffix("_failed") {
                    recordFailure(fields)
                }
            }
        }

        return LiveThroughputMetrics(
            uploads5m: uploads5m,
            uploads15m: uploads15m,
            deletes15m: deletes15m,
            conversions15m: conversions15m,
            blockedAssets15m: blockedAssetIds.count,
            failureAttempts15m: failureAttempts15m,
            assetlessFailureAttempts15m: assetlessFailureAttempts15m,
            bytesSaved15m: bytesSaved15m,
            windowSeconds: window15m,
            coveredSeconds: coveredSeconds
        )
    }

    private struct MetricEvent {
        let name: String
        let age: TimeInterval
        let fields: [String: Any]
    }

    private static func metricEvents(_ text: String, now: TimeInterval) -> [MetricEvent] {
        text.components(separatedBy: .newlines).compactMap { line in
            guard
                let data = line.data(using: .utf8),
                let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let event = object["event"] as? String
            else {
                return nil
            }
            let timestamp = (object["at_unix_seconds"] as? TimeInterval)
                ?? (object["t_unix_seconds"] as? TimeInterval)
            guard let timestamp else {
                return nil
            }
            let age = now - timestamp
            guard age >= 0 else {
                return nil
            }
            let fields = object["fields"] as? [String: Any] ?? [:]
            return MetricEvent(name: event, age: age, fields: fields)
        }
    }

    private static func boolField(_ key: String, fields: [String: Any]) -> Bool {
        if let value = fields[key] as? Bool {
            return value
        }
        if let value = fields[key] as? NSNumber {
            return value.boolValue
        }
        return false
    }

    private static func int64Field(_ key: String, fields: [String: Any]) -> Int64? {
        if let value = fields[key] as? Int64 {
            return value
        }
        if let value = fields[key] as? Int {
            return Int64(value)
        }
        if let value = fields[key] as? NSNumber {
            return value.int64Value
        }
        return nil
    }

    private static func stringArrayField(_ key: String, fields: [String: Any]) -> [String] {
        (fields[key] as? [Any] ?? []).compactMap { value in
            guard let value = value as? String, !value.isEmpty else {
                return nil
            }
            return value
        }
    }
}

final class DashboardStream<Value>: ObservableObject {
    let name: String
    @Published var value: Value?
    @Published var refreshedAt: Date?
    @Published var error: String?
    @Published var inFlight = false

    init(_ name: String) {
        self.name = name
    }

    func beginRefresh() -> Bool {
        guard !inFlight else {
            return false
        }
        inFlight = true
        return true
    }

    func finish(value newValue: Value?, error newError: String?) {
        if let newValue {
            value = newValue
        }
        error = newError
        refreshedAt = Date()
        inFlight = false
    }
}

struct ProcessResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

let bundledHelperPath = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin"

func configureBundledHelperEnvironment(_ process: Process) {
    var environment = ProcessInfo.processInfo.environment
    environment["PATH"] = bundledHelperPath
    process.environment = environment
    AppLogger.log("bundled_helper_environment_configured", fields: ["path": bundledHelperPath])
}

private final class ProcessOutputReader: @unchecked Sendable {
    private let handle: FileHandle
    private let queue: DispatchQueue
    private var data = Data()

    init(handle: FileHandle, label: String) {
        self.handle = handle
        queue = DispatchQueue(label: label)
    }

    func start(in group: DispatchGroup) {
        group.enter()
        queue.async { [self] in
            data = handle.readDataToEndOfFile()
            group.leave()
        }
    }

    func string() -> String {
        String(data: data, encoding: .utf8) ?? ""
    }
}

func runCapturedProcess(
    executableURL: URL,
    arguments: [String],
    bundledHelper: Bool = false
) throws -> ProcessResult {
    let process = Process()
    process.executableURL = executableURL
    process.arguments = arguments
    if bundledHelper {
        configureBundledHelperEnvironment(process)
    }
    let stdout = Pipe()
    let stderr = Pipe()
    process.standardOutput = stdout
    process.standardError = stderr

    try process.run()

    let readers = DispatchGroup()
    let stdoutReader = ProcessOutputReader(
        handle: stdout.fileHandleForReading,
        label: "com.icloudpd-optimizer.process.stdout"
    )
    let stderrReader = ProcessOutputReader(
        handle: stderr.fileHandleForReading,
        label: "com.icloudpd-optimizer.process.stderr"
    )
    stdoutReader.start(in: readers)
    stderrReader.start(in: readers)
    process.waitUntilExit()
    readers.wait()

    return ProcessResult(
        status: process.terminationStatus,
        stdout: stdoutReader.string(),
        stderr: stderrReader.string()
    )
}

enum AppLogger {
    private static let queue = DispatchQueue(label: "com.icloudpd-optimizer.app-log")
    private static let maxBytes: UInt64 = 5 * 1024 * 1024

    static var path: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/iCloudPD Optimizer/app.log")
            .path
    }

    static func log(_ event: String, fields: [String: Any] = [:]) {
        queue.sync {
            write(event, fields: fields)
        }
    }

    private static func write(_ event: String, fields: [String: Any]) {
        do {
            let url = URL(fileURLWithPath: path)
            let directory = url.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            rotateIfNeeded(url)

            var payload: [String: Any] = [
                "at_unix_seconds": Date().timeIntervalSince1970,
                "event": event,
                "pid": ProcessInfo.processInfo.processIdentifier,
            ]
            if !fields.isEmpty {
                payload["fields"] = fields
            }
            let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
            let line = data + Data("\n".utf8)

            if FileManager.default.fileExists(atPath: url.path) {
                let handle = try FileHandle(forWritingTo: url)
                try handle.seekToEnd()
                try handle.write(contentsOf: line)
                try handle.close()
            } else {
                try line.write(to: url, options: .atomic)
            }
        } catch {
            fputs("failed to write app log: \(error)\n", stderr)
        }
    }

    private static func rotateIfNeeded(_ url: URL) {
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let size = attributes[.size] as? UInt64 ?? 0
            guard size >= maxBytes else {
                return
            }
            let rotated = URL(fileURLWithPath: url.path + ".1")
            if FileManager.default.fileExists(atPath: rotated.path) {
                try FileManager.default.removeItem(at: rotated)
            }
            try FileManager.default.moveItem(at: url, to: rotated)
        } catch {
            return
        }
    }
}

func appBookmarkStoreURL() throws -> URL {
    let base = try FileManager.default.url(
        for: .applicationSupportDirectory,
        in: .userDomainMask,
        appropriateFor: nil,
        create: true
    )
    return base
        .appendingPathComponent("iCloudPD Optimizer", isDirectory: true)
        .appendingPathComponent("access-bookmarks.plist")
}

func loadStoredFolderAccess() -> [URL] {
    do {
        let data = try Data(contentsOf: try appBookmarkStoreURL())
        let stored = try PropertyListDecoder().decode(StoredBookmarks.self, from: data)
        var urls: [URL] = []
        for bookmark in stored.bookmarks {
            var stale = false
            let url = try URL(
                resolvingBookmarkData: bookmark,
                options: [.withSecurityScope],
                relativeTo: nil,
                bookmarkDataIsStale: &stale
            )
            if url.startAccessingSecurityScopedResource() {
                urls.append(url)
            }
        }
        AppLogger.log("folder_bookmarks_loaded", fields: ["accessible_count": urls.count])
        return urls
    } catch {
        AppLogger.log("folder_bookmarks_unavailable", fields: ["error": String(describing: error)])
        return []
    }
}

func runBundledHelperAndExit(args: [String]) -> Never {
    AppLogger.log("app_launched", fields: ["args": args, "log_path": AppLogger.path])
    guard let helper = Bundle.main.resourceURL?.appendingPathComponent("icloudpd-optimizer") else {
        AppLogger.log("helper_missing")
        fputs("missing bundled icloudpd-optimizer helper\n", stderr)
        exit(1)
    }
    let process = Process()
    process.executableURL = helper
    process.arguments = args
    configureBundledHelperEnvironment(process)
    process.standardInput = FileHandle.standardInput
    process.standardOutput = FileHandle.standardOutput
    process.standardError = FileHandle.standardError
    do {
        let scopedAccess = loadStoredFolderAccess()
        AppLogger.log("helper_starting", fields: [
            "helper": helper.path,
            "args": args,
            "security_scoped_resources": scopedAccess.count,
        ])
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        let terminationQueue = DispatchQueue(label: "icloudpd-optimizer.helper-signals")
        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: terminationQueue)
        let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: terminationQueue)
        for (source, signalNumber) in [(termSource, SIGTERM), (intSource, SIGINT)] {
            source.setEventHandler {
                AppLogger.log("helper_terminating", fields: ["signal": signalNumber])
                if process.isRunning {
                    process.terminate()
                }
            }
            source.resume()
        }
        defer {
            termSource.cancel()
            intSource.cancel()
            for url in scopedAccess {
                url.stopAccessingSecurityScopedResource()
            }
        }
        try process.run()
        process.waitUntilExit()
        AppLogger.log("helper_exited", fields: ["status": process.terminationStatus])
        exit(process.terminationStatus)
    } catch {
        AppLogger.log("helper_failed", fields: ["error": String(describing: error)])
        fputs("failed to run bundled helper: \(error)\n", stderr)
        exit(1)
    }
}

enum DashboardFormat {
    static let time: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    static let refreshed: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "MMM d, HH:mm:ss"
        return formatter
    }()

    static func bytes(_ bytes: Int64) -> String {
        let gib = Double(bytes) / 1_073_741_824
        if gib >= 1 {
            return String(format: "%.2f GiB", gib)
        }
        let mib = Double(bytes) / 1_048_576
        return String(format: "%.1f MiB", mib)
    }

    static func duration(_ seconds: TimeInterval) -> String {
        if seconds >= 3600 {
            return String(format: "%.1fh", seconds / 3600)
        }
        if seconds >= 60 {
            return String(format: "%.0fm %.0fs", floor(seconds / 60), seconds.truncatingRemainder(dividingBy: 60))
        }
        return String(format: "%.0fs", seconds)
    }

    static func rate(_ count: Int, over seconds: TimeInterval) -> String {
        guard seconds > 0 else {
            return "0/hr"
        }
        return String(format: "%.1f/hr", Double(count) * 3600 / seconds)
    }

    static func stage(_ stage: String?) -> String {
        guard let stage, !stage.isEmpty else {
            return "waiting"
        }
        switch stage {
        case "convert_heic":
            return "Convert"
        case "verify_converted_heics":
            return "Quality check"
        case "upload_verified_heics":
            return "Upload HEIC"
        case "record_local_mirrors":
            return "NAS proof"
        case "delete_original_assets":
            return "Safe delete"
        case "resolve_original_assets":
            return "Match RAW"
        case "nas_verified":
            return "Ready"
        default:
            return stage
                .replacingOccurrences(of: "_", with: " ")
                .replacingOccurrences(of: "heic", with: "HEIC")
                .capitalized
        }
    }

    static func label(_ key: String) -> String {
        switch key {
        case "delete_approved":
            return "delete approved"
        case "active_lifecycle":
            return "active"
        case "resolve_original_assets":
            return "matching original"
        case "convert_heic":
            return "ready to convert"
        case "verify_converted_heics":
            return "ready to verify"
        case "upload_verified_heics":
            return "ready to upload"
        case "record_local_mirrors":
            return "needs mirror proof"
        case "delete_original_assets":
            return "ready to delete"
        case "conversion_verified":
            return "verified"
        case "upload_verified":
            return "uploaded"
        default:
            return key.replacingOccurrences(of: "_", with: " ")
        }
    }

    static func failureBucket(_ key: String) -> String {
        switch key {
        case "blocked_original_asset_resolve":
            return "unmatched iCloud originals"
        case "retryable_conversion_timeout":
            return "conversion timed out"
        case "retryable_raw_staging_timeout":
            return "RAW staging timed out"
        case "retryable_stale_heic_output":
            return "stale HEIC output"
        case "retryable_stale_staged_raw":
            return "stale staged RAW"
        case "blocked_visual_content":
            return "visual check blocked"
        case "blocked_missing_embedded_preview":
            return "missing preview"
        case "failed_other":
            return "other failures"
        default:
            return label(key)
        }
    }

    static func compactAsset(_ assetId: String?) -> String {
        guard let assetId, !assetId.isEmpty else {
            return "no asset"
        }
        if assetId.count <= 18 {
            return assetId
        }
        return "\(assetId.prefix(8))...\(assetId.suffix(6))"
    }
}

final class DashboardController: NSObject {
    private let model: DashboardViewModel
    private var window: NSWindow?

    init(
        configPath: String,
        prepareNASAuthorization: @escaping () throws -> NASAuthorization,
        primeNASAuthorization: @escaping (MonitorAccessPlan) throws -> PrimeStatus
    ) {
        self.model = DashboardViewModel(
            configPath: configPath,
            prepareNASAuthorization: prepareNASAuthorization,
            primeNASAuthorization: primeNASAuthorization
        )
    }

    func show() {
        AppLogger.log("dashboard_opened", fields: ["config_path": model.configPath])
        if let window {
            bringDashboardWindowForward(window)
            model.start()
            return
        }
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: dashboardMinimumWindowSize),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "iCloudPD Optimizer"
        window.titlebarAppearsTransparent = true
        window.toolbarStyle = .unified
        window.isReleasedWhenClosed = false
        window.collectionBehavior.formUnion([.moveToActiveSpace, .fullScreenAuxiliary])
        placeWindowOnActiveScreen(window)
        window.contentView = NSHostingView(rootView: OptimizerDashboardView(model: model))
        self.window = window
        bringDashboardWindowForward(window)
        model.start()
    }

    private func bringDashboardWindowForward(_ window: NSWindow) {
        NSApp.setActivationPolicy(.regular)
        NSApp.unhide(nil)
        placeWindowOnActiveScreen(window)
        ensureWindowVisible(window)
        if window.isMiniaturized {
            window.deminiaturize(nil)
        }
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        pulseWindowAboveOthers(window)
        NSRunningApplication.current.activate(options: [.activateAllWindows])
        NSApp.activate(ignoringOtherApps: true)
        logWindowState("dashboard_window_fronted", window: window)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { [weak self, weak window] in
            guard let self, let window else {
                return
            }
            self.ensureWindowVisible(window)
            if window.isMiniaturized {
                window.deminiaturize(nil)
            }
            NSApp.setActivationPolicy(.regular)
            NSApp.unhide(nil)
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            NSApp.activate(ignoringOtherApps: true)
            self.logWindowState("dashboard_window_fronted_after_activation", window: window)
        }
    }

    private func ensureWindowVisible(_ window: NSWindow) {
        if window.frame.width < dashboardMinimumWindowSize.width || window.frame.height < dashboardMinimumWindowSize.height {
            window.setFrame(NSRect(origin: window.frame.origin, size: dashboardMinimumWindowSize), display: false)
        }
        let visibleOnScreen = NSScreen.screens.contains { screen in
            screen.visibleFrame.intersects(window.frame)
        }
        if !visibleOnScreen {
            placeWindowOnActiveScreen(window)
        }
    }

    private func placeWindowOnActiveScreen(_ window: NSWindow) {
        let mouse = NSEvent.mouseLocation
        let screen = NSScreen.screens.first { $0.frame.contains(mouse) } ?? NSScreen.main ?? NSScreen.screens.first
        guard let visibleFrame = screen?.visibleFrame else {
            window.center()
            return
        }
        let width = min(dashboardMinimumWindowSize.width, visibleFrame.width - 32)
        let height = min(dashboardMinimumWindowSize.height, visibleFrame.height - 32)
        let origin = NSPoint(
            x: visibleFrame.midX - width / 2,
            y: visibleFrame.midY - height / 2
        )
        window.setFrame(NSRect(x: origin.x, y: origin.y, width: width, height: height), display: false)
    }

    private func pulseWindowAboveOthers(_ window: NSWindow) {
        let previousLevel = window.level
        window.level = .floating
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak window] in
            guard let window, window.level == .floating else {
                return
            }
            window.level = previousLevel
            AppLogger.log("dashboard_window_level_restored")
        }
    }

    private func logWindowState(_ event: String, window: NSWindow) {
        let screenFrame = window.screen?.visibleFrame ?? .zero
        AppLogger.log(event, fields: [
            "is_visible": window.isVisible,
            "is_key": window.isKeyWindow,
            "is_main": window.isMainWindow,
            "is_miniaturized": window.isMiniaturized,
            "window_x": window.frame.minX,
            "window_y": window.frame.minY,
            "window_width": window.frame.width,
            "window_height": window.frame.height,
            "screen_x": screenFrame.minX,
            "screen_y": screenFrame.minY,
            "screen_width": screenFrame.width,
            "screen_height": screenFrame.height,
        ])
    }
}

final class DashboardViewModel: ObservableObject {
    let configPath: String
    @Published var refreshInFlight = false
    @Published private(set) var nasAuthorizationInFlight = false
    let service = DashboardStream<ServiceSnapshot>("service")
    let stats = DashboardStream<MonitorStatsEnvelope>("stats")
    let queue = DashboardStream<MonitorQueuePayload>("queue")
    let scans = DashboardStream<[ScanSummary]>("scans")
    let logs = DashboardStream<DashboardLogState>("logs")

    private let prepareNASAuthorization: () throws -> NASAuthorization
    private let primeNASAuthorization: (MonitorAccessPlan) throws -> PrimeStatus
    private let workQueue = DispatchQueue(label: "com.icloudpd-optimizer.dashboard-refresh", qos: .utility, attributes: .concurrent)
    private let queueReportHelperQueue = DispatchQueue(label: "com.icloudpd-optimizer.dashboard-queue-report-helper", qos: .utility)
    private let nasAuthorizationQueue = DispatchQueue(label: "com.icloudpd-optimizer.nas-authorization", qos: .userInitiated)
    private var timers: [Timer] = []
    private var queueReportInFlight = false
    private var queueReportRefreshedAt: Date?

    init(
        configPath: String,
        prepareNASAuthorization: @escaping () throws -> NASAuthorization,
        primeNASAuthorization: @escaping (MonitorAccessPlan) throws -> PrimeStatus
    ) {
        self.configPath = configPath
        self.prepareNASAuthorization = prepareNASAuthorization
        self.primeNASAuthorization = primeNASAuthorization
    }

    deinit {
        timers.forEach { $0.invalidate() }
    }

    func start() {
        guard timers.isEmpty else {
            refreshNow()
            return
        }
        refreshNow()
        timers = [
            scheduledLiveTimer(interval: dashboardLogRefreshInterval) { [weak self] in self?.refreshLogs() },
            scheduledLiveTimer(interval: dashboardQueueReportRefreshInterval) { [weak self] in self?.refreshQueue() },
            scheduledLiveTimer(interval: 6) { [weak self] in self?.refreshScans() },
            scheduledLiveTimer(interval: 10) { [weak self] in self?.refreshService() },
            scheduledLiveTimer(interval: 10) { [weak self] in self?.refreshStats() },
        ]
    }

    func refreshNow() {
        refreshInFlight = true
        let group = DispatchGroup()
        refreshLogs(group: group)
        refreshScans(group: group)
        refreshService(group: group)
        refreshStats(group: group)
        refreshQueue(group: group, force: true)
        group.notify(queue: .main) { [weak self] in
            self?.refreshInFlight = false
        }
    }

    func refreshLogs(group: DispatchGroup? = nil) {
        refreshStream(logs, group: group) {
            let logPaths = self.serviceLogPaths()
            let latestEvents = self.tailText(path: logPaths.stderr, maxBytes: dashboardLogTailBytes)
            return DashboardLogState(
                raw: latestEvents,
                events: self.parseLatestEvents(latestEvents),
                workerActivities: self.parseWorkerActivities(latestEvents),
                throughput: DashboardMetricsParser.liveThroughputMetrics(latestEvents)
            )
        }
    }

    func refreshQueue(group: DispatchGroup? = nil, force: Bool = false) {
        refreshQueueReport(group: group, force: force)
    }

    func refreshScans(group: DispatchGroup? = nil) {
        refreshStream(scans, group: group) {
            let logPaths = self.serviceLogPaths()
            return Array(self.loadRecentScans(from: logPaths.stdout).suffix(40))
        }
    }

    func refreshService(group: DispatchGroup? = nil) {
        refreshStream(service, group: group) {
            self.loadServiceSnapshot()
        }
    }

    func refreshStats(group: DispatchGroup? = nil) {
        refreshStream(stats, group: group) {
            let config = self.loadMonitorConfig()
            return try self.loadStatsEnvelope(config: config)
        }
    }

    func authorizeNAS() {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.authorizeNAS()
            }
            return
        }
        guard !nasAuthorizationInFlight else {
            return
        }

        nasAuthorizationInFlight = true
        AppLogger.log("nas_authorization_started")
        do {
            let authorization = try self.prepareNASAuthorization()
            nasAuthorizationQueue.async {
                let result = Result {
                    try self.primeNASAuthorization(authorization.plan)
                }
                DispatchQueue.main.async {
                    self.completeNASAuthorization(result, authorization: authorization)
                }
            }
        } catch {
            completeNASAuthorization(.failure(error), authorization: nil)
        }
    }

    private func completeNASAuthorization(
        _ result: Result<PrimeStatus, Error>,
        authorization: NASAuthorization?
    ) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.completeNASAuthorization(result, authorization: authorization)
            }
            return
        }
        authorization?.stopAccessingSecurityScopedResources()
        nasAuthorizationInFlight = false

        switch result {
        case .success:
            AppLogger.log("nas_authorization_succeeded")
            showAlert(title: "NAS Access Verified", message: "The app can read and write the configured NAS paths.")
            refreshNow()
        case .failure(let error):
            AppLogger.log("nas_authorization_failed", fields: ["error": String(describing: error)])
            showAlert(title: "NAS Access Failed", message: String(describing: error))
        }
    }

    private func scheduledLiveTimer(interval: TimeInterval, action: @escaping () -> Void) -> Timer {
        let timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { _ in
            action()
        }
        timer.tolerance = min(0.5, interval * 0.2)
        return timer
    }

    private func refreshStream<Value>(
        _ stream: DashboardStream<Value>,
        group: DispatchGroup? = nil,
        load: @escaping () throws -> Value
    ) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async {
                self.refreshStream(stream, group: group, load: load)
            }
            return
        }
        guard stream.beginRefresh() else {
            return
        }
        group?.enter()
        workQueue.async {
            let result = Result {
                try load()
            }
            DispatchQueue.main.async {
                switch result {
                case .success(let value):
                    stream.finish(value: value, error: nil)
                case .failure(let error):
                    let message = "\(stream.name): \(error)"
                    AppLogger.log("dashboard_stream_refresh_failed", fields: [
                        "stream": stream.name,
                        "error": message,
                    ])
                    stream.finish(value: nil, error: message)
                }
                group?.leave()
            }
        }
    }

    private func refreshQueueReport(group: DispatchGroup? = nil, force: Bool = false) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async {
                self.refreshQueueReport(group: group, force: force)
            }
            return
        }
        guard !queueReportInFlight else {
            return
        }
        if !force,
           let queueReportRefreshedAt,
           Date().timeIntervalSince(queueReportRefreshedAt) < dashboardQueueReportRefreshInterval
        {
            return
        }
        guard queue.beginRefresh() else {
            return
        }

        queueReportInFlight = true
        group?.enter()
        queueReportHelperQueue.async {
            let queueResult = Result { try self.loadQueueReport() }
            DispatchQueue.main.async {
                self.finishQueueReportRefresh(queueResult: queueResult)
                group?.leave()
            }
        }
    }

    private func finishQueueReportRefresh(queueResult: Result<MonitorQueuePayload, Error>) {
        switch queueResult {
        case .success(let value):
            queue.finish(value: value, error: nil)
        case .failure(let error):
            let message = "queue: \(error)"
            AppLogger.log("dashboard_stream_refresh_failed", fields: [
                "stream": queue.name,
                "error": message,
            ])
            queue.finish(value: nil, error: message)
        }

        queueReportRefreshedAt = Date()
        queueReportInFlight = false
    }

    private func loadStatsEnvelope(config: DashboardMonitorConfig?) throws -> MonitorStatsEnvelope {
        let decoder = JSONDecoder()
        let statsPath = config?.statsPath ?? defaultStatsPath()
        let data = try Data(contentsOf: URL(fileURLWithPath: statsPath))
        let stats = try decoder.decode(MonitorStatsPayload.self, from: data)
        return MonitorStatsEnvelope(stats: stats, verifiedMetrics: nil)
    }

    private func loadQueueReport() throws -> MonitorQueuePayload {
        do {
            let chunkLimit = max(64, loadMonitorConfig()?.rollingWorkerCount ?? 64)
            let result = try runBundledHelper(arguments: [
                "monitor", "queue",
                "--config", configPath,
                "--json",
                "--chunks", "\(chunkLimit)",
            ])
            guard result.status == 0 else {
                throw PrimeError(result.stderr.isEmpty ? result.stdout : result.stderr)
            }
            return try JSONDecoder().decode(MonitorQueuePayload.self, from: Data(result.stdout.utf8))
        } catch {
            throw PrimeError("queue helper: \(error)")
        }
    }

    private func showAlert(title: String, message: String) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.showAlert(title: title, message: message)
            }
            return
        }
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func loadServiceSnapshot() -> ServiceSnapshot {
        do {
            let label = "gui/\(getuid())/com.icloudpd-optimizer.monitor"
            let result = try runCapturedProcess(
                executableURL: URL(fileURLWithPath: "/bin/launchctl"),
                arguments: ["print", label]
            )
            let output = result.stdout + result.stderr
            let program = firstMatch(in: output, prefix: "program =")
            let pid = firstMatch(in: output, prefix: "pid =")
            let running = output.contains("state = running")
            let native = program?.contains(".app/Contents/MacOS/ICloudPDOptimizerApp") == true
            return ServiceSnapshot(running: running, nativeApp: native, pid: pid, program: program, raw: output)
        } catch {
            return ServiceSnapshot(running: false, nativeApp: false, pid: nil, program: nil, raw: String(describing: error))
        }
    }

    private func firstMatch(in text: String, prefix: String) -> String? {
        text.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { $0.hasPrefix(prefix) }?
            .replacingOccurrences(of: prefix, with: "")
            .trimmingCharacters(in: .whitespaces)
    }

    private func serviceLogPaths() -> (stdout: String, stderr: String) {
        let plistURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.icloudpd-optimizer.monitor.plist")
        if let plist = NSDictionary(contentsOf: plistURL) {
            let stdout = plist["StandardOutPath"] as? String
            let stderr = plist["StandardErrorPath"] as? String
            if let stdout, let stderr {
                return (stdout, stderr)
            }
        }
        let base = URL(fileURLWithPath: configPath).deletingPathExtension().path
        return ("\(base).stdout.log", "\(base).stderr.log")
    }

    private func loadMonitorConfig() -> DashboardMonitorConfig? {
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: configPath))
            return try JSONDecoder().decode(DashboardMonitorConfig.self, from: data)
        } catch {
            return nil
        }
    }

    private func defaultStatsPath() -> String {
        URL(fileURLWithPath: configPath).deletingPathExtension().appendingPathExtension("monitor-stats.json").path
    }

    private func loadRecentScans(from path: String) -> [ScanSummary] {
        let text = tailText(path: path, maxBytes: 1_500_000)
        let decoder = JSONDecoder()
        return text.components(separatedBy: .newlines).compactMap { line in
            guard let data = line.data(using: .utf8) else {
                return nil
            }
            return try? decoder.decode(ScanSummary.self, from: data)
        }.sorted { $0.finishedUnixSeconds < $1.finishedUnixSeconds }
    }

    private func parseLatestEvents(_ text: String) -> [DashboardLogEvent] {
        Array(text.components(separatedBy: .newlines)
            .suffix(80)
            .compactMap(parseMonitorEvent)
            .suffix(24))
    }

    private func parseWorkerActivities(_ text: String) -> [Int: WorkerActivity] {
        var activities: [Int: WorkerActivity] = [:]
        let lines = Array(text.components(separatedBy: .newlines).suffix(700))
        let latestScanStarted = lines.compactMap { line -> TimeInterval? in
            guard
                let data = line.data(using: .utf8),
                let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                return nil
            }
            return (object["scan_started_unix_seconds"] as? TimeInterval)
                ?? (object["started_unix_seconds"] as? TimeInterval)
        }.max()
        for line in lines {
            guard
                let data = line.data(using: .utf8),
                let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let event = object["event"] as? String,
                let fields = object["fields"] as? [String: Any],
                let workerId = intField("worker_id", fields: fields)
            else {
                continue
            }
            let scanStarted = (object["scan_started_unix_seconds"] as? TimeInterval)
                ?? (object["started_unix_seconds"] as? TimeInterval)
            if let latestScanStarted, scanStarted != latestScanStarted {
                continue
            }
            let timestamp = (object["at_unix_seconds"] as? TimeInterval)
                ?? (object["t_unix_seconds"] as? TimeInterval)
            let updatedAt = timestamp.map(Date.init(timeIntervalSince1970:))
            let assetId = stringField("asset_id", fields: fields)
            switch event {
            case "rolling_lifecycle_worker_asset_started":
                activities[workerId] = WorkerActivity(
                    workerId: workerId,
                    assetId: assetId,
                    stage: "picked",
                    detail: "state \(stringField("state_before", fields: fields) ?? "unknown")",
                    updatedAt: updatedAt,
                    finished: false
                )
            case "rolling_lifecycle_worker_stage_started":
                activities[workerId] = WorkerActivity(
                    workerId: workerId,
                    assetId: assetId,
                    stage: stringField("stage", fields: fields) ?? "stage",
                    detail: "started",
                    updatedAt: updatedAt,
                    finished: false
                )
            case "rolling_lifecycle_worker_stage_waiting":
                let stageName = stringField("stage", fields: fields) ?? "stage"
                let waitingDetail = stageName == "convert_heic" && intField("convert_stage_slots", fields: fields) != nil
                    ? "waiting for convert slot"
                    : "waiting for CPU slot"
                activities[workerId] = WorkerActivity(
                    workerId: workerId,
                    assetId: assetId,
                    stage: stageName,
                    detail: waitingDetail,
                    updatedAt: updatedAt,
                    finished: false
                )
            case "rolling_lifecycle_worker_stage_finished":
                activities[workerId] = WorkerActivity(
                    workerId: workerId,
                    assetId: assetId,
                    stage: stringField("stage", fields: fields) ?? "stage",
                    detail: "state \(stringField("state_after", fields: fields) ?? "unknown")",
                    updatedAt: updatedAt,
                    finished: false
                )
            case "rolling_lifecycle_worker_asset_finished":
                let stateAfter = stringField("state_after", fields: fields)
                let readyForBatchDelete = stateAfter == "delete_original_assets" || stateAfter == "upload_verified"
                activities[workerId] = WorkerActivity(
                    workerId: workerId,
                    assetId: assetId,
                    stage: readyForBatchDelete ? "record_local_mirrors" : "asset finished",
                    detail: readyForBatchDelete ? "ready for batch delete" : "state \(stateAfter ?? "unknown")",
                    updatedAt: updatedAt,
                    finished: true
                )
            default:
                continue
            }
        }
        return activities
    }

    private func parseMonitorEvent(_ line: String) -> DashboardLogEvent? {
        guard
            let data = line.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let event = object["event"] as? String
        else {
            return nil
        }
        let fields = object["fields"] as? [String: Any] ?? [:]
        let timestamp = (object["at_unix_seconds"] as? TimeInterval).map(Date.init(timeIntervalSince1970:))
        let asset = stringField("asset_id", fields: fields)
        let worker = stringField("worker_id", fields: fields)
        let stage = stringField("stage", fields: fields)

        switch event {
        case "rolling_lifecycle_worker_pool_started":
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: "\(stringField("worker_slots", fields: fields) ?? "0") workers online",
                detail: "\(stringField("queued_assets", fields: fields) ?? "0") assets queued",
                tone: .active
            )
        case "rolling_lifecycle_worker_asset_started":
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: "Worker \(worker ?? "-") picked \(asset ?? "asset")",
                detail: "state \(stringField("state_before", fields: fields) ?? "unknown")",
                tone: .active
            )
        case "rolling_lifecycle_worker_stage_started":
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: "Worker \(worker ?? "-") started \(prettyStage(stage))",
                detail: asset ?? "",
                tone: .active
            )
        case "rolling_lifecycle_worker_stage_waiting":
            let cpuSlots = stringField("cpu_stage_slots", fields: fields) ?? "0"
            let convertSlots = stringField("convert_stage_slots", fields: fields)
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: "Worker \(worker ?? "-") waiting for \(prettyStage(stage))",
                detail: convertSlots.map { "\(cpuSlots) CPU / \($0) convert slots" } ?? "\(cpuSlots) CPU slots",
                tone: .warning
            )
        case "stale_conversion_artifacts_removed":
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: "Removed stale conversion output",
                detail: "\(asset ?? "asset") - \(stringField("removed", fields: fields) ?? "0") files",
                tone: .warning
            )
        case "conversion_finished":
            let ok = boolField("converted", fields: fields)
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: ok ? "Converted \(asset ?? "asset")" : "Conversion blocked",
                detail: ok ? DashboardFormat.bytes(int64Field("heic_size_bytes", fields: fields) ?? 0) : stringField("error", fields: fields) ?? "",
                tone: ok ? .success : .blocked
            )
        case "heic_verify_finished":
            let ok = boolField("verified", fields: fields)
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: ok ? "Verified HEIC" : "Verification failed",
                detail: asset ?? stringField("error", fields: fields) ?? "",
                tone: ok ? .success : .blocked
            )
        case "upload_finished":
            let ok = boolField("uploaded", fields: fields)
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: ok ? "Uploaded replacement" : "Upload failed",
                detail: ok ? asset ?? "" : stringField("error", fields: fields) ?? "",
                tone: ok ? .success : .warning
            )
        case "delete_batch_finished":
            let count = stringField("recorded_deletes", fields: fields) ?? "0"
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: "Deleted \(count) original RAWs",
                detail: DashboardFormat.bytes(int64Field("bytes_saved", fields: fields) ?? 0) + " saved",
                tone: .success
            )
        case "scan_finished":
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: "Scan finished",
                detail: "\(stringField("conversions_completed", fields: fields) ?? "0") converted - \(stringField("failures", fields: fields) ?? "0") failures",
                tone: .neutral
            )
        default:
            return DashboardLogEvent(
                timestamp: timestamp,
                event: event,
                title: event.replacingOccurrences(of: "_", with: " "),
                detail: asset ?? "",
                tone: .neutral
            )
        }
    }

    private func stringField(_ key: String, fields: [String: Any]) -> String? {
        guard let value = fields[key] else {
            return nil
        }
        if let string = value as? String {
            return string
        }
        if let number = value as? NSNumber {
            return number.stringValue
        }
        return "\(value)"
    }

    private func boolField(_ key: String, fields: [String: Any]) -> Bool {
        if let value = fields[key] as? Bool {
            return value
        }
        if let value = fields[key] as? NSNumber {
            return value.boolValue
        }
        return false
    }

    private func int64Field(_ key: String, fields: [String: Any]) -> Int64? {
        if let value = fields[key] as? Int64 {
            return value
        }
        if let value = fields[key] as? Int {
            return Int64(value)
        }
        if let value = fields[key] as? NSNumber {
            return value.int64Value
        }
        return nil
    }

    private func intField(_ key: String, fields: [String: Any]) -> Int? {
        if let value = fields[key] as? Int {
            return value
        }
        if let value = fields[key] as? NSNumber {
            return value.intValue
        }
        if let value = fields[key] as? String {
            return Int(value)
        }
        return nil
    }

    private func prettyStage(_ stage: String?) -> String {
        (stage ?? "stage")
            .replacingOccurrences(of: "_", with: " ")
            .replacingOccurrences(of: "heic", with: "HEIC")
    }

    private func tailText(path: String, maxBytes: UInt64) -> String {
        do {
            let url = URL(fileURLWithPath: path)
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let end = try handle.seekToEnd()
            let start = end > maxBytes ? end - maxBytes : 0
            try handle.seek(toOffset: start)
            let data = try handle.readToEnd() ?? Data()
            var text = String(data: data, encoding: .utf8) ?? ""
            if start > 0, let firstNewline = text.firstIndex(of: "\n") {
                text.removeSubrange(text.startIndex...firstNewline)
            }
            return text
        } catch {
            return ""
        }
    }

    private func runBundledHelper(arguments: [String]) throws -> ProcessResult {
        guard let helper = Bundle.main.resourceURL?.appendingPathComponent("icloudpd-optimizer") else {
            throw PrimeError("missing bundled icloudpd-optimizer helper")
        }
        return try runCapturedProcess(
            executableURL: helper,
            arguments: arguments,
            bundledHelper: true
        )
    }
}

struct OptimizerDashboardView: View {
    @ObservedObject var model: DashboardViewModel

    var body: some View {
        VStack(spacing: 0) {
            MainDashboardView(model: model)
        }
        .frame(minWidth: 1100, minHeight: 760)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct SidebarView: View {
    @ObservedObject var service: DashboardStream<ServiceSnapshot>
    let configPath: String

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 10) {
                RoundedRectangle(cornerRadius: 6)
                    .fill(Color.blue)
                    .frame(width: 28, height: 28)
                    .overlay(Image(systemName: "icloud.and.arrow.up").foregroundStyle(.white).font(.system(size: 15, weight: .semibold)))
                VStack(alignment: .leading, spacing: 1) {
                    Text("iCloudPD")
                        .font(.system(size: 15, weight: .semibold))
                    Text("Optimizer")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                SidebarItem(icon: "gauge.with.dots.needle.bottom.50percent", title: "Overview", selected: true)
                SidebarItem(icon: "rectangle.stack.badge.play", title: "Workers", selected: false)
                SidebarItem(icon: "externaldrive.badge.icloud", title: "NAS Proofs", selected: false)
                SidebarItem(icon: "exclamationmark.triangle", title: "Failures", selected: false)
                SidebarItem(icon: "doc.text.magnifyingglass", title: "Logs", selected: false)
            }

            Spacer()

            VStack(alignment: .leading, spacing: 10) {
                StatusCapsule(
                    text: service.value?.running == true ? "Service running" : "Service stopped",
                    tone: service.value?.running == true ? .success : .warning
                )
                Text(URL(fileURLWithPath: configPath).lastPathComponent)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .help(configPath)
            }
        }
        .padding(18)
        .background(.regularMaterial)
    }
}

struct SidebarItem: View {
    let icon: String
    let title: String
    let selected: Bool

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: icon)
                .frame(width: 18)
            Text(title)
            Spacer()
        }
        .font(.system(size: 13, weight: selected ? .semibold : .regular))
        .foregroundStyle(selected ? .primary : .secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(selected ? Color(nsColor: .selectedContentBackgroundColor).opacity(0.12) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

struct MainDashboardView: View {
    @ObservedObject var model: DashboardViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HeaderView(
                    model: model,
                    service: model.service,
                    queue: model.queue,
                    stats: model.stats,
                    logs: model.logs
                )
                OperatorSummaryPanel(stats: model.stats, queue: model.queue, logs: model.logs)
                PipelineOverviewPanel(queue: model.queue, logs: model.logs)
                HStack(alignment: .top, spacing: 14) {
                    WorkerQueuePanel(queue: model.queue, logs: model.logs)
                        .frame(maxWidth: .infinity)
                    VStack(spacing: 14) {
                        FailureBacklogPanel(queue: model.queue, stats: model.stats, logs: model.logs)
                        ThroughputPanel(logs: model.logs)
                    }
                    .frame(width: 310)
                }
                LiveLogPanel(logs: model.logs)
            }
            .padding(20)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct HeaderView: View {
    @ObservedObject var model: DashboardViewModel
    @ObservedObject var service: DashboardStream<ServiceSnapshot>
    @ObservedObject var queue: DashboardStream<MonitorQueuePayload>
    @ObservedObject var stats: DashboardStream<MonitorStatsEnvelope>
    @ObservedObject var logs: DashboardStream<DashboardLogState>

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 7) {
                Text("iCloudPD Optimizer")
                    .font(.system(size: 24, weight: .semibold))
                HStack(spacing: 8) {
                    StatusCapsule(
                        text: service.value?.nativeApp == true ? "Monitor running" : "Checking monitor",
                        tone: service.value?.nativeApp == true ? .success : .warning
                    )
                    if let queue = queue.value {
                        StatusCapsule(
                            text: "\(workerSlotCount(queue: queue, logs: logs.value)) workers",
                            tone: .active
                        )
                        StatusCapsule(
                            text: "\(queue.jobs) CPU",
                            tone: .active
                        )
                        StatusCapsule(
                            text: "\(queue.convertStageSlots ?? max(1, queue.jobs / 2)) encoders",
                            tone: .active
                        )
                    }
                }
                Text(refreshDetail)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            Spacer()
            Button {
                model.authorizeNAS()
            } label: {
                Label("Authorize NAS", systemImage: "externaldrive.badge.checkmark")
            }
            .disabled(model.nasAuthorizationInFlight)
            Button {
                model.refreshNow()
            } label: {
                Label(model.refreshInFlight ? "Refreshing" : "Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(model.refreshInFlight)
        }
    }

    private var refreshDetail: String {
        [
            refreshText("service", service.refreshedAt, service.inFlight),
            refreshText("queue", queue.refreshedAt, queue.inFlight),
            refreshText("totals", stats.refreshedAt, stats.inFlight),
            refreshText("activity", logs.refreshedAt, logs.inFlight),
        ].joined(separator: "  |  ")
    }

    private func refreshText(_ name: String, _ date: Date?, _ inFlight: Bool) -> String {
        if inFlight {
            return "\(name) updating"
        }
        return "\(name) \(date.map { DashboardFormat.refreshed.string(from: $0) } ?? "loading")"
    }
}

struct OperatorSummaryPanel: View {
    @ObservedObject var stats: DashboardStream<MonitorStatsEnvelope>
    @ObservedObject var queue: DashboardStream<MonitorQueuePayload>
    @ObservedObject var logs: DashboardStream<DashboardLogState>

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: operatorSummaryPanelTitle, detail: summaryDetail)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), spacing: 10)], spacing: 10) {
                ForEach(metrics, id: \.title) { metric in
                    MetricTile(metric: metric)
                }
            }
        }
    }

    private var summaryDetail: String {
        let live = logs.value?.throughput ?? .empty
        if let error = queue.error ?? stats.error ?? logs.error {
            return error
        }
        return "live events, \(live.coverageDetail())"
    }

    private var metrics: [DashboardMetric] {
        operatorSummaryMetrics(
            statsPayload: stats.value?.stats,
            queuePayload: queue.value,
            logs: logs.value
        )
    }
}

private let operatorSummaryPanelTitle = "Lifetime totals and recent activity"

private func operatorSummaryMetrics(
    statsPayload: MonitorStatsPayload?,
    queuePayload: MonitorQueuePayload?,
    logs: DashboardLogState?
) -> [DashboardMetric] {
    let live = logs?.throughput ?? .empty
    let selectedBatch = currentRunAssetCount(queue: queuePayload, logs: logs)
    let workerCount = workerSlotCount(queue: queuePayload, logs: logs)
    let workerCounts = workerActivitySummary(queue: queuePayload, logs: logs)
    let manifestBacklog = queuePayload?.stateCounts["failed"]
        ?? statsPayload?.stateCounts["failed"]
        ?? 0
    let noActionRecords = queuePayload?.verifiedMetrics.noActionRecords
        ?? queuePayload?.verifiedMetrics.stateCounts["no_action"]
        ?? statsPayload?.noActionRecords
        ?? statsPayload?.stateCounts["no_action"]
        ?? 0
    let needsReviewRecords = queuePayload?.verifiedMetrics.needsReviewRecords
        ?? queuePayload?.verifiedMetrics.stateCounts["needs_review"]
        ?? statsPayload?.needsReviewRecords
        ?? statsPayload?.stateCounts["needs_review"]
        ?? 0
    let verified = queuePayload?.verifiedMetrics
    let displayedWorkers = max(workerCount, workerCounts.total)
    let occupiedWorkers = workerCounts.busy + workerCounts.waiting
    let workerDetail = queuePayload == nil
        ? "\(workerCounts.busy) running, queue loading"
        : "\(workerCounts.busy) running, \(workerCounts.waiting) waiting, \(selectedBatch) assets"
    let blockedDetail = "\(live.failureAttempts15m) retry/failure attempts; \(live.assetlessFailureAttempts15m) without asset ID"
    let spaceSaved = spaceSavedMetric(verified: verified, live: live)
    return [
        DashboardMetric(title: "Workers occupied", value: "\(occupiedWorkers)/\(displayedWorkers)", detail: workerDetail, tone: occupiedWorkers > 0 ? .active : .warning),
        DashboardMetric(title: "Converted (15m)", value: "\(live.conversions15m)", detail: "\(live.hourlyRate(live.conversions15m)) current pace", tone: .active),
        DashboardMetric(title: "Uploaded total", value: verified.map { "\($0.uploadedReplacements)" } ?? "--", detail: "\(live.uploads15m) uploaded in the last 15m", tone: .active),
        DashboardMetric(title: "Deleted total", value: verified.map { "\($0.deletedOriginals)" } ?? "--", detail: "\(live.deletes15m) deleted in the last 15m", tone: .success),
        DashboardMetric(title: "No action total", value: "\(noActionRecords)", detail: "terminal reconciliation outcomes; not queued", tone: .neutral),
        DashboardMetric(title: "Needs review total", value: "\(needsReviewRecords)", detail: "terminal reconciliation outcomes; not failed or queued", tone: .warning),
        spaceSaved,
        DashboardMetric(title: "Blocked assets (15m)", value: "\(live.blockedAssets15m)", detail: blockedDetail, tone: live.failureAttempts15m > 0 || manifestBacklog > 0 ? .warning : .success),
    ]
}

private func spaceSavedMetric(
    verified: VerifiedMetricsPayload?,
    live: LiveThroughputMetrics
) -> DashboardMetric {
    guard let verified else {
        return DashboardMetric(
            title: "Space saved total",
            value: "--",
            detail: "verified manifest loading",
            tone: .warning
        )
    }
    if verified.deletedSizeMetricsComplete {
        return DashboardMetric(
            title: "Space saved total",
            value: DashboardFormat.bytes(verified.verifiedBytesSaved),
            detail: "\(DashboardFormat.bytes(live.bytesSaved15m)) saved in the last 15m",
            tone: .success
        )
    }

    let missing = verified.deletedRecordsMissingSizeProofs
    if missing == 0 {
        return DashboardMetric(
            title: "Space saved unavailable",
            value: "--",
            detail: "lifetime size metric unavailable or out of supported range",
            tone: .warning
        )
    }
    let missingDetail = "\(missing) deleted \(missing == 1 ? "record" : "records") missing size proofs"
    let hasVerifiedSubset = verified.deletedOriginals > missing
    return DashboardMetric(
        title: hasVerifiedSubset ? "Space saved (partial)" : "Space saved unavailable",
        value: hasVerifiedSubset ? DashboardFormat.bytes(verified.verifiedBytesSaved) : "--",
        detail: missingDetail,
        tone: .warning
    )
}

struct StageLoadStrip: View {
    let stageCounts: [String: Int]

    var body: some View {
        let maxCount = max(1, pipelineStages.map { stageCounts[$0.key] ?? 0 }.max() ?? 0)
        HStack(spacing: 8) {
            ForEach(pipelineStages) { stage in
                StageLoadCell(
                    title: stage.title,
                    count: stageCounts[stage.key] ?? 0,
                    maxCount: maxCount
                )
            }
        }
    }
}

struct StageLoadCell: View {
    let title: String
    let count: Int
    let maxCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(title)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer()
                Text("\(count)")
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .monospacedDigit()
            }
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.secondary.opacity(0.12))
                    Capsule()
                        .fill(count == maxCount && count > 0 ? Color.orange.opacity(0.75) : Color.blue.opacity(0.65))
                        .frame(width: count > 0 ? max(4, proxy.size.width * CGFloat(count) / CGFloat(maxCount)) : 0)
                }
            }
            .frame(height: 5)
        }
        .padding(8)
        .frame(maxWidth: .infinity, minHeight: 52)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color(nsColor: .windowBackgroundColor)))
    }
}

struct DashboardMetric {
    let title: String
    let value: String
    let detail: String
    let tone: DashboardEventTone
}

struct MetricTile: View {
    let metric: DashboardMetric

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(metric.title)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.secondary)
                Spacer()
                Circle().fill(metric.tone.color).frame(width: 7, height: 7)
            }
            Text(metric.value)
                .font(.system(size: 22, weight: .semibold, design: .rounded))
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(metric.detail)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(12)
        .frame(height: 92)
        .background(CardBackground())
    }
}

private enum WorkerFilter: String, CaseIterable, Identifiable {
    case active = "Active"
    case waiting = "Waiting"
    case idle = "Idle"
    case all = "All"

    var id: String { rawValue }
}

struct WorkerQueuePanel: View {
    @ObservedObject var queue: DashboardStream<MonitorQueuePayload>
    @ObservedObject var logs: DashboardStream<DashboardLogState>
    @State private var filter: WorkerFilter = .all

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            let activities = logs.value?.workerActivities ?? [:]
            let workers = workerSnapshots(activities: activities)
            let now = Date()
            let active = workers.filter { workerDisplayState(activities[$0.workerId], now: now) == .active }.count
            let waiting = workers.filter { workerDisplayState(activities[$0.workerId], now: now) == .waiting }.count
            let idle = workers.filter { workerDisplayState(activities[$0.workerId], now: now) == .idle }.count
            let displayedWorkers = workers.filter { worker in
                let state = workerDisplayState(activities[worker.workerId], now: now)
                return matchesFilter(state)
            }
            let detail = queue.value == nil
                ? "\(active) active from live logs; queue report loading"
                : "\(active) active, \(waiting) waiting, \(idle) idle"
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Workers")
                        .font(.system(size: 14, weight: .semibold))
                    Text(detail)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Picker("Worker state", selection: $filter) {
                    ForEach(WorkerFilter.allCases) { item in
                        Text(item.rawValue).tag(item)
                    }
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                .frame(width: 300)
            }
            if workers.isEmpty {
                EmptyPanelText("No active worker slots")
            } else if displayedWorkers.isEmpty {
                EmptyPanelText("No workers in this state")
            } else {
                VStack(spacing: 0) {
                    WorkerTableHeader()
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(displayedWorkers) { worker in
                                Divider()
                                WorkerLifecycleRow(worker: worker, activity: activities[worker.workerId])
                            }
                        }
                    }
                    .frame(height: 360)
                }
            }
        }
        .padding(14)
        .background(CardBackground())
    }

    private func workerSnapshots(activities: [Int: WorkerActivity]) -> [WorkerLaneSnapshot] {
        let planned = Dictionary(uniqueKeysWithValues: (queue.value?.workerSlots ?? []).map { ($0.workerId, $0) })
        let maxWorkers = max(workerSlotCount(queue: queue.value, logs: logs.value), planned.keys.max() ?? 0, activities.keys.max() ?? 0)
        guard maxWorkers > 0 else {
            return []
        }
        let now = Date()
        let snapshots = (1...maxWorkers).map { workerId in
            let plan = planned[workerId]
            return WorkerLaneSnapshot(
                workerId: workerId,
                firstAssetId: plan?.firstAssetId,
                nextStage: plan?.nextStage
            )
        }
        return snapshots.sorted { left, right in
            let leftRank = workerLaneRank(left, activity: activities[left.workerId], now: now)
            let rightRank = workerLaneRank(right, activity: activities[right.workerId], now: now)
            if leftRank == rightRank {
                let leftStageRank = workerLaneStageRank(left, activity: activities[left.workerId], now: now)
                let rightStageRank = workerLaneStageRank(right, activity: activities[right.workerId], now: now)
                if leftStageRank != rightStageRank {
                    return leftStageRank < rightStageRank
                }
                return left.workerId < right.workerId
            }
            return leftRank < rightRank
        }
    }

    private func matchesFilter(_ state: WorkerDisplayState) -> Bool {
        switch filter {
        case .active:
            return state == .active
        case .waiting:
            return state == .waiting
        case .idle:
            return state == .idle
        case .all:
            return true
        }
    }
}

struct WorkerTableHeader: View {
    var body: some View {
        HStack(spacing: 12) {
            Text("Worker").frame(width: 64, alignment: .leading)
            Text("Asset").frame(width: 142, alignment: .leading)
            Text("Current work")
            Spacer()
            Text("Updated").frame(width: 72, alignment: .trailing)
        }
        .font(.system(size: 10, weight: .medium))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 6)
    }
}

struct WorkerLifecycleRow: View {
    let worker: WorkerLaneSnapshot
    let activity: WorkerActivity?

    var body: some View {
        let freshActivity = freshActivity(now: Date())
        let stage = freshActivity?.stage ?? worker.nextStage ?? "waiting"
        let assetId = freshActivity?.assetId ?? worker.firstAssetId
        HStack(spacing: 12) {
            Text("#\(worker.workerId)")
                .font(.system(size: 13, weight: .semibold, design: .rounded))
                .monospacedDigit()
                .frame(width: 64, alignment: .leading)
            Text(DashboardFormat.compactAsset(assetId))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 142, alignment: .leading)
                .lineLimit(1)
            VStack(alignment: .leading, spacing: 3) {
                StagePill(text: statusText(stage: stage), tone: rowTone)
                Text(statusDetail)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Text(activityAgeText(now: Date()))
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 72, alignment: .trailing)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 9)
        .help(freshActivity == nil ? "planned next work" : freshActivity?.detail ?? "live event")
    }

    private var rowTone: DashboardEventTone {
        guard let activity = freshActivity(now: Date()) else {
            return worker.nextStage == nil ? .neutral : .warning
        }
        if activity.finished == true {
            return .success
        }
        if activity.detail.hasPrefix("waiting for ") == true {
            return .warning
        }
        return .active
    }

    private func statusText(stage: String) -> String {
        guard let activity = freshActivity(now: Date()) else {
            if worker.nextStage != nil {
                return "Queued: \(DashboardFormat.stage(stage))"
            }
            return "Idle"
        }
        if activity.finished == true {
            if activity.detail == "ready for batch delete" {
                return "Ready to delete"
            }
            return "Done"
        }
        if activity.detail.hasPrefix("waiting for ") == true {
            return "Waiting: \(DashboardFormat.stage(stage))"
        }
        return DashboardFormat.stage(stage)
    }

    private var statusDetail: String {
        guard let activity = freshActivity(now: Date()) else {
            return worker.nextStage == nil ? "no planned asset" : "planned next work"
        }
        return activity.detail
    }

    private func activityAgeText(now: Date) -> String {
        guard let updatedAt = activity?.updatedAt else {
            return "--"
        }
        let seconds = max(0, Int(now.timeIntervalSince(updatedAt)))
        if seconds < 60 {
            return "\(seconds)s"
        }
        return "\(seconds / 60)m \(seconds % 60)s"
    }

    private func freshActivity(now: Date) -> WorkerActivity? {
        guard let activity, isFreshWorkerActivity(activity, now: now) else {
            return nil
        }
        return activity
    }
}

struct PipelineOverviewPanel: View {
    @ObservedObject var queue: DashboardStream<MonitorQueuePayload>
    @ObservedObject var logs: DashboardStream<DashboardLogState>

    var body: some View {
        let payload = queue.value
        let workers = workerSlotCount(queue: payload, logs: logs.value)
        let stageCounts = displayStageCounts(payload, logs: logs.value)
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(
                title: "Live asset flow",
                detail: queueDetail(workers: workers, payload: payload, logs: logs.value)
            )
            StageLoadStrip(stageCounts: stageCounts)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Lifecycle queue overview")
    }

    private func queueDetail(workers: Int, payload: MonitorQueuePayload?, logs: DashboardLogState?) -> String {
        if payload == nil, logs?.workerActivities.isEmpty == false {
            return "live activity; queue report loading"
        }
        let cpuJobs = cpuWorkerCount(queue: payload)
        let convertSlots = payload?.convertStageSlots ?? max(1, cpuJobs / 2)
        return "\(workers) workers, \(cpuJobs) CPU slots, \(convertSlots) encoders"
    }
}

struct ThroughputPanel: View {
    @ObservedObject var logs: DashboardStream<DashboardLogState>

    var body: some View {
        let live = logs.value?.throughput ?? .empty
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: "Recent throughput", detail: live.coverageDetail())
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 2), spacing: 10) {
                ForEach(throughputStats(from: live)) { stat in
                    ThroughputStatTile(stat: stat)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(CardBackground())
    }
}

struct ThroughputStatTile: View {
    let stat: ThroughputStat

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(stat.label)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(.secondary)
                Spacer()
                Circle().fill(stat.tone.color).frame(width: 6, height: 6)
            }
            Text(stat.value)
                .font(.system(size: 20, weight: .semibold, design: .rounded))
                .monospacedDigit()
            Text(stat.detail)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color(nsColor: .controlBackgroundColor)))
    }
}

struct FailureBacklogPanel: View {
    @ObservedObject var queue: DashboardStream<MonitorQueuePayload>
    @ObservedObject var stats: DashboardStream<MonitorStatsEnvelope>
    @ObservedObject var logs: DashboardStream<DashboardLogState>

    var body: some View {
        let live = logs.value?.throughput ?? .empty
        let failures = sortedCounts(queue.value?.failureCounts ?? [:])
        let manifestFailureTotal = queue.value?.stateCounts["failed"]
            ?? stats.value?.verifiedMetrics?.stateCounts["failed"]
            ?? stats.value?.stats.stateCounts["failed"]
            ?? failures.map(\.value).reduce(0, +)
        let recentDetail = "\(live.blockedAssets15m) distinct assets; \(live.failureAttempts15m) attempts, \(live.assetlessFailureAttempts15m) without asset ID in 15m"
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: "Blocked assets", detail: recentDetail)
            if failures.isEmpty && live.failureAttempts15m == 0 && manifestFailureTotal == 0 {
                EmptyPanelText("No fresh failures. Delete still requires NAS, upload, and original-match proof.")
            } else {
                HStack(spacing: 12) {
                    StatLabel(title: "distinct in 15m", value: "\(live.blockedAssets15m)")
                    Divider().frame(height: 34)
                    StatLabel(title: "attempts in 15m", value: "\(live.failureAttempts15m)")
                    Divider().frame(height: 34)
                    StatLabel(title: "held for review", value: "\(manifestFailureTotal)")
                }
                ForEach(failures.prefix(5), id: \.key) { item in
                    HStack(spacing: 8) {
                        Circle().fill(Color.orange).frame(width: 7, height: 7)
                        Text(DashboardFormat.failureBucket(item.key))
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        Spacer()
                        Text("\(item.value)")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(CardBackground())
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Failure backlog")
    }
}

struct LiveLogPanel: View {
    @ObservedObject var logs: DashboardStream<DashboardLogState>

    var body: some View {
        let events = logs.value?.events ?? []
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: "Live Log", detail: "Human-readable monitor events")
            if events.isEmpty {
                EmptyPanelText("Waiting for monitor events")
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(events.reversed()) { event in
                            LiveLogRow(event: event)
                            if event.id != events.first?.id {
                                Divider()
                            }
                        }
                    }
                }
                .frame(height: 220)
            }
        }
        .padding(14)
        .background(CardBackground())
    }
}

struct LiveLogRow: View {
    let event: DashboardLogEvent

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Circle().fill(event.tone.color).frame(width: 8, height: 8)
            Text(event.timestamp.map { DashboardFormat.time.string(from: $0) } ?? "--:--:--")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 64, alignment: .leading)
            Text(event.title)
                .font(.system(size: 12, weight: .medium))
                .lineLimit(1)
            Text(event.detail)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
        }
        .padding(.vertical, 7)
    }
}

struct InspectorPanel: View {
    @ObservedObject var queue: DashboardStream<MonitorQueuePayload>
    @ObservedObject var stats: DashboardStream<MonitorStatsEnvelope>
    @ObservedObject var logs: DashboardStream<DashboardLogState>

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Inspector")
                .font(.system(size: 18, weight: .semibold))
            if let asset = queue.value?.activeLifecycle.first {
                VStack(alignment: .leading, spacing: 12) {
                    Text(asset.assetId)
                        .font(.system(size: 12, design: .monospaced))
                        .lineLimit(2)
                    InspectorRow(title: "State", value: DashboardFormat.label(asset.state))
                    InspectorRow(title: "Next", value: DashboardFormat.stage(asset.nextStage))
                    InspectorRow(title: "RAW size", value: DashboardFormat.bytes(asset.rawSizeBytes))
                }
                .padding(12)
                .background(CardBackground())
            }
            VStack(alignment: .leading, spacing: 10) {
                PanelHeader(title: "Blocked Backlog", detail: "manifest")
                ForEach(sortedCounts(queue.value?.failureCounts ?? [:]).prefix(8), id: \.key) { item in
                    HStack {
                        Text(DashboardFormat.failureBucket(item.key))
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                        Spacer()
                        Text("\(item.value)")
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    }
                }
            }
            .padding(12)
            .background(CardBackground())
            Spacer()
            let errors = streamErrors
            if !errors.isEmpty {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(errors, id: \.self) { error in
                        Text(error)
                            .font(.system(size: 11))
                            .foregroundStyle(.red)
                            .lineLimit(3)
                    }
                }
            }
        }
        .padding(18)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.55))
    }

    private var streamErrors: [String] {
        [queue.error, stats.error, logs.error].compactMap { $0 }
    }
}

struct PanelHeader: View {
    let title: String
    let detail: String?

    var body: some View {
        HStack {
            Text(title)
                .font(.system(size: 14, weight: .semibold))
            Spacer()
            if let detail {
                Text(detail)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
        }
    }
}

struct StatusCapsule: View {
    let text: String
    let tone: DashboardEventTone

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(tone.color).frame(width: 7, height: 7)
            Text(text)
                .font(.system(size: 11, weight: .medium))
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 5)
        .background(tone.color.opacity(0.12))
        .clipShape(Capsule())
    }
}

struct StagePill: View {
    let text: String
    let tone: DashboardEventTone

    var body: some View {
        Text(text)
            .font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .background(tone.color.opacity(0.12))
            .foregroundStyle(tone.color)
            .clipShape(Capsule())
    }
}

struct StatLabel: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.system(size: 16, weight: .semibold, design: .rounded))
                .monospacedDigit()
            Text(title)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct InspectorRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
                .lineLimit(1)
        }
        .font(.system(size: 12))
    }
}

struct EmptyPanelText: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.system(size: 12))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, minHeight: 72)
    }
}

struct CardBackground: View {
    var body: some View {
        RoundedRectangle(cornerRadius: 8, style: .continuous)
            .fill(Color(nsColor: .controlBackgroundColor))
            .overlay(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(Color.secondary.opacity(0.12), lineWidth: 1)
            )
    }
}

struct SparklineShape: Shape {
    let values: [TimeInterval]

    func path(in rect: CGRect) -> Path {
        guard values.count > 1, let minValue = values.min(), let maxValue = values.max() else {
            return Path()
        }
        let span = max(1, maxValue - minValue)
        var path = Path()
        for (index, value) in values.enumerated() {
            let x = rect.minX + rect.width * CGFloat(index) / CGFloat(values.count - 1)
            let y = rect.maxY - rect.height * CGFloat((value - minValue) / span)
            let point = CGPoint(x: x, y: y)
            index == 0 ? path.move(to: point) : path.addLine(to: point)
        }
        return path
    }
}

extension DashboardEventTone {
    var color: Color {
        switch self {
        case .active:
            return .blue
        case .success:
            return .green
        case .warning:
            return .orange
        case .blocked:
            return .red
        case .neutral:
            return .secondary
        }
    }
}

private func sortedCounts(_ counts: [String: Int]) -> [(key: String, value: Int)] {
    counts.sorted {
        if $0.value == $1.value {
            return $0.key < $1.key
        }
        return $0.value > $1.value
    }
}

private enum WorkerDisplayState: String {
    case active
    case waiting
    case idle
}

private func workerDisplayState(_ activity: WorkerActivity?, now: Date) -> WorkerDisplayState {
    guard let activity, isFreshWorkerActivity(activity, now: now), !activity.finished else {
        return .idle
    }
    if activity.detail.hasPrefix("waiting for ") {
        return .waiting
    }
    return .active
}

private func activeWorkerCount(queue: MonitorQueuePayload?, logs: DashboardLogState?) -> Int {
    let now = Date()
    return logs?.workerActivities.values.filter { activity in
        workerDisplayState(activity, now: now) == .active
    }.count ?? 0
}

private func workerActivitySummary(queue: MonitorQueuePayload?, logs: DashboardLogState?) -> (busy: Int, waiting: Int, finished: Int, total: Int) {
    let now = Date()
    let freshActivities = logs?.workerActivities.values.filter {
        isFreshWorkerActivity($0, now: now)
    } ?? []
    let busy = freshActivities.filter { workerDisplayState($0, now: now) == .active }.count
    let waiting = freshActivities.filter { workerDisplayState($0, now: now) == .waiting }.count
    let finished = freshActivities.filter(\.finished).count
    let total = max(workerSlotCount(queue: queue, logs: logs), logs?.workerActivities.keys.max() ?? 0)
    return (busy: busy, waiting: waiting, finished: finished, total: total)
}

private func liveStageCounts(_ logs: DashboardLogState?) -> [String: Int] {
    let now = Date()
    return logs?.workerActivities.values.reduce(into: [:]) { counts, activity in
        guard
            isFreshWorkerActivity(activity, now: now),
            !activity.finished,
            workerLifecycleStages.contains(activity.stage)
        else {
            return
        }
        counts[activity.stage, default: 0] += 1
    } ?? [:]
}

private func displayStageCounts(_ queue: MonitorQueuePayload?, logs: DashboardLogState?) -> [String: Int] {
    let liveCounts = liveStageCounts(logs)
    if !liveCounts.isEmpty {
        return liveCounts
    }
    return activeStageCounts(queue)
}

private func waitingWorkerCount(stage: String, logs: DashboardLogState?) -> Int {
    let now = Date()
    return logs?.workerActivities.values.filter { activity in
        isFreshWorkerActivity(activity, now: now)
            && !activity.finished
            && activity.stage == stage
            && activity.detail.hasPrefix("waiting for ")
    }.count ?? 0
}

private func isFreshWorkerActivity(_ activity: WorkerActivity, now: Date) -> Bool {
    guard let updatedAt = activity.updatedAt else {
        return false
    }
    return now.timeIntervalSince(updatedAt) <= workerActivityFreshWindow
}

private func workerLaneRank(_ lane: WorkerLaneSnapshot, activity: WorkerActivity?, now: Date) -> Int {
    switch workerDisplayState(activity, now: now) {
    case .active:
        return 0
    case .waiting:
        return 1
    case .idle:
        break
    }
    if lane.nextStage != nil {
        return 2
    }
    if activity != nil {
        return 3
    }
    return 4
}

private func workerLaneStageRank(_ lane: WorkerLaneSnapshot, activity: WorkerActivity?, now: Date) -> Int {
    let stage: String?
    if let activity, isFreshWorkerActivity(activity, now: now) {
        stage = activity.stage
    } else {
        stage = lane.nextStage
    }
    guard let stage else {
        return workerLifecycleStages.count + 1
    }
    return workerLifecycleStages.firstIndex(of: stage) ?? workerLifecycleStages.count
}

private func workerSlotCount(queue: MonitorQueuePayload?, logs: DashboardLogState?) -> Int {
    if let workerSlots = queue?.rollingWorkerCount, workerSlots > 0 {
        return workerSlots
    }
    if let cpuJobs = queue?.jobs, cpuJobs > 0 {
        return cpuJobs
    }
    if let maxWorkerId = logs?.workerActivities.keys.max(), maxWorkerId > 0 {
        return maxWorkerId
    }
    return 0
}

private func cpuWorkerCount(queue: MonitorQueuePayload?) -> Int {
    max(queue?.jobs ?? 0, 0)
}

private func currentRunAssetCount(queue: MonitorQueuePayload?, logs: DashboardLogState?) -> Int {
    let queued = activeLifecycleCount(queue)
    if queued > 0 {
        return queued
    }
    return logs?.workerActivities.count ?? 0
}

private func activeLifecycleCount(_ queue: MonitorQueuePayload?) -> Int {
    if let count = queue?.activeLifecycle.count, count > 0 {
        return count
    }
    return queue?.queueCounts["active_lifecycle"] ?? 0
}

private func activeStageCounts(_ queue: MonitorQueuePayload?) -> [String: Int] {
    guard let queue, !queue.activeLifecycle.isEmpty else {
        return queue?.queueCounts ?? [:]
    }
    return queue.activeLifecycle.reduce(into: [:]) { counts, asset in
        counts[asset.nextStage, default: 0] += 1
    }
}

private func bottleneckStage(_ queue: MonitorQueuePayload?, logs: DashboardLogState? = nil) -> (title: String, count: Int) {
    let activeCounts = displayStageCounts(queue, logs: logs)
    if activeCounts.isEmpty {
        guard queue != nil else {
            return ("Loading", 0)
        }
        return ("Idle", 0)
    }
    guard queue != nil || logs?.workerActivities.isEmpty == false else {
        return ("Loading", 0)
    }
    let stages = pipelineStages.map { stage in
        (title: stage.title, count: activeCounts[stage.key] ?? 0)
    }
    return stages.max { $0.count < $1.count } ?? ("Idle", 0)
}

private func throughputStats(from live: LiveThroughputMetrics) -> [ThroughputStat] {
    [
        ThroughputStat(
            id: "converted",
            label: "Converted",
            value: "\(live.conversions15m)",
            detail: "\(live.hourlyRate(live.conversions15m)) pace",
            tone: .active
        ),
        ThroughputStat(
            id: "uploaded",
            label: "Uploaded",
            value: "\(live.uploads15m)",
            detail: "\(live.hourlyRate(live.uploads15m)) pace; \(live.uploads5m) in 5m",
            tone: .active
        ),
        ThroughputStat(
            id: "deleted",
            label: "Deleted",
            value: "\(live.deletes15m)",
            detail: "\(live.hourlyRate(live.deletes15m)) pace; \(DashboardFormat.bytes(live.bytesSaved15m))",
            tone: .success
        ),
        ThroughputStat(
            id: "failures",
            label: "Blocked assets",
            value: "\(live.blockedAssets15m)",
            detail: "\(live.failureAttempts15m) attempts; \(live.assetlessFailureAttempts15m) without asset ID",
            tone: live.blockedAssets15m > 0 || live.assetlessFailureAttempts15m > 0 ? .warning : .success
        ),
    ]
}

private func isPrimeAccessArgs(_ args: [String]) -> Bool {
    args.count >= 2 && args[0] == "service" && args[1] == "prime-access"
}

private func isMonitorRunArgs(_ args: [String]) -> Bool {
    args.count >= 2 && args[0] == "monitor" && args[1] == "run"
}

private func shouldProxyLaunchArguments(_ args: [String]) -> Bool {
    guard !args.isEmpty else {
        return false
    }
    return !isPrimeAccessArgs(args) && !isMonitorRunArgs(args)
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private struct DashboardConfigResolution {
        let path: String
        let source: String
    }

    private var dashboard: DashboardController?
    private var serviceProcess: Process?
    private var serviceScopedAccess: [URL] = []
    private var serviceSignalSources: [DispatchSourceSignal] = []
    private let serviceSignalQueue = DispatchQueue(label: "icloudpd-optimizer.app-service-signals")
    private let primeAccessQueue = DispatchQueue(label: "com.icloudpd-optimizer.prime-access", qos: .userInitiated)

    func applicationDidFinishLaunching(_ notification: Notification) {
        let args = Array(CommandLine.arguments.dropFirst())
        AppLogger.log("app_launched", fields: ["args": args, "log_path": AppLogger.path])
        if args.isEmpty {
            showDashboard()
            return
        }
        if isPrimeAccessArgs(args) {
            runPrimeAccess(args: args)
            return
        }
        if isMonitorRunArgs(args) {
            startServiceHelper(args: args)
            return
        }
        runHelper(args: args)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        AppLogger.log("dashboard_reopen_requested", fields: ["has_visible_windows": flag])
        showDashboard()
        return false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        serviceProcess?.isRunning != true
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let process = serviceProcess, process.isRunning {
            process.terminate()
        }
        stopServiceScopedAccess()
    }

    private func showDashboard() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        if let dashboard {
            AppLogger.log("dashboard_reused")
            dashboard.show()
            return
        }

        guard let resolution = resolveDashboardConfigPath() else {
            AppLogger.log("dashboard_failed", fields: ["error": "missing monitor config path"])
            showResult(PrimeStatus(
                ok: false,
                configPath: "",
                readRoots: [],
                writeCanaryDir: nil,
                error: "missing monitor config path"
            ))
            NSApp.terminate(nil)
            return
        }
        let configPath = resolution.path
        AppLogger.log("dashboard_config_resolved", fields: [
            "config_path": configPath,
            "source": resolution.source,
        ])
        dashboard = DashboardController(
            configPath: configPath,
            prepareNASAuthorization: { [weak self] in
                guard let self else {
                    throw PrimeError("app delegate is unavailable")
                }
                return try self.prepareNASAuthorization(configPath: configPath)
            },
            primeNASAuthorization: { [weak self] plan in
                guard let self else {
                    throw PrimeError("app delegate is unavailable")
                }
                return try self.primeNASAuthorization(plan: plan)
            }
        )
        dashboard?.show()
    }

    private func prepareNASAuthorization(configPath: String) throws -> NASAuthorization {
        let plan = try loadAccessPlan(configPath: configPath, writeCanaryOverride: nil)
        return try requestNASAuthorization(for: plan)
    }

    private func primeNASAuthorization(plan: MonitorAccessPlan) throws -> PrimeStatus {
        return try primeAccess(plan: plan)
    }

    private func runHelper(args: [String]) {
        runBundledHelperAndExit(args: args)
    }

    private func startServiceHelper(args: [String]) {
        NSApp.setActivationPolicy(.accessory)
        AppLogger.log("service_helper_launch_requested", fields: ["args": args])
        guard let helper = Bundle.main.resourceURL?.appendingPathComponent("icloudpd-optimizer") else {
            AppLogger.log("helper_missing")
            fputs("missing bundled icloudpd-optimizer helper\n", stderr)
            exit(1)
        }

        let process = Process()
        process.executableURL = helper
        process.arguments = args
        configureBundledHelperEnvironment(process)
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        serviceScopedAccess = loadStoredFolderAccess()
        serviceProcess = process
        installServiceSignalHandlers(for: process)
        process.terminationHandler = { [weak self] process in
            AppLogger.log("service_helper_exited", fields: ["status": process.terminationStatus])
            DispatchQueue.main.async {
                self?.cancelServiceSignalHandlers()
                self?.stopServiceScopedAccess()
                exit(process.terminationStatus)
            }
        }

        do {
            try process.run()
            AppLogger.log("service_helper_started", fields: [
                "helper": helper.path,
                "security_scoped_resources": serviceScopedAccess.count,
            ])
        } catch {
            AppLogger.log("service_helper_failed", fields: ["error": String(describing: error)])
            fputs("failed to run bundled helper: \(error)\n", stderr)
            stopServiceScopedAccess()
            exit(1)
        }
    }

    private func installServiceSignalHandlers(for process: Process) {
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        serviceSignalSources = [SIGTERM, SIGINT].map { signalNumber in
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: serviceSignalQueue)
            source.setEventHandler {
                AppLogger.log("service_helper_terminating", fields: ["signal": signalNumber])
                if process.isRunning {
                    process.terminate()
                }
            }
            source.resume()
            return source
        }
    }

    private func cancelServiceSignalHandlers() {
        serviceSignalSources.forEach { $0.cancel() }
        serviceSignalSources.removeAll()
    }

    private func stopServiceScopedAccess() {
        for url in serviceScopedAccess {
            url.stopAccessingSecurityScopedResource()
        }
        serviceScopedAccess.removeAll()
    }

    private func runPrimeAccess(args: [String]) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.runPrimeAccess(args: args)
            }
            return
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)

        let explicitConfigPath = argumentValue("--config", in: args)
        let resolvedConfig = explicitConfigPath.map {
            DashboardConfigResolution(path: $0, source: "argument")
        } ?? resolveDashboardConfigPath()
        let configPath = resolvedConfig?.path
        let statusFile = argumentValue("--status-file", in: args)
        let writeCanaryOverride = argumentValue("--write-canary-dir", in: args)

        do {
            guard let configPath, !configPath.isEmpty else {
                throw PrimeError("missing monitor config path")
            }
            AppLogger.log("prime_access_started", fields: [
                "config_path": configPath,
                "source": resolvedConfig?.source ?? "",
            ])
            let plan = try loadAccessPlan(
                configPath: configPath,
                writeCanaryOverride: writeCanaryOverride
            )
            let authorization = shouldRequestFolderAccess(args: args)
                ? try requestNASAuthorization(for: plan)
                : NASAuthorization(plan: plan, scopedAccess: [])
            primeAccessQueue.async {
                let result = Result {
                    try self.primeNASAuthorization(plan: authorization.plan)
                }
                DispatchQueue.main.async {
                    self.finishPrimeAccess(
                        result,
                        authorization: authorization,
                        configPath: configPath,
                        statusFile: statusFile,
                        shouldShowResult: args.isEmpty
                    )
                }
            }
        } catch {
            finishPrimeAccess(
                .failure(error),
                authorization: nil,
                configPath: configPath ?? "",
                statusFile: statusFile,
                shouldShowResult: args.isEmpty
            )
        }
    }

    private func finishPrimeAccess(
        _ result: Result<PrimeStatus, Error>,
        authorization: NASAuthorization?,
        configPath: String,
        statusFile: String?,
        shouldShowResult: Bool
    ) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.finishPrimeAccess(
                    result,
                    authorization: authorization,
                    configPath: configPath,
                    statusFile: statusFile,
                    shouldShowResult: shouldShowResult
                )
            }
            return
        }
        authorization?.stopAccessingSecurityScopedResources()

        let status: PrimeStatus
        switch result {
        case .success(let report):
            status = report
            AppLogger.log("prime_access_succeeded", fields: [
                "read_roots": report.readRoots,
                "write_canary_dir": report.writeCanaryDir ?? "",
            ])
        case .failure(let error):
            status = PrimeStatus(
                ok: false,
                configPath: configPath,
                readRoots: [],
                writeCanaryDir: nil,
                error: String(describing: error)
            )
            AppLogger.log("prime_access_failed", fields: ["error": String(describing: error)])
        }

        if let statusFile {
            writeStatus(status, to: statusFile)
        }

        if shouldShowResult || !status.ok {
            showResult(status)
        }
        NSApp.terminate(nil)
    }

    private func loadAccessPlan(
        configPath: String,
        writeCanaryOverride: String?
    ) throws -> MonitorAccessPlan {
        let configURL = URL(fileURLWithPath: configPath)
        let configData = try Data(contentsOf: configURL)
        guard
            let json = try JSONSerialization.jsonObject(with: configData) as? [String: Any],
            let downloadRoot = json["download_root"] as? String
        else {
            throw PrimeError("monitor config is missing download_root")
        }

        var roots = uniquePaths([
            downloadRoot,
            json["nas_root"] as? String,
            json["mirror_root"] as? String,
        ])
        if roots.isEmpty {
            roots = [downloadRoot]
        }

        let writeDir = writeCanaryOverride
            ?? json["mirror_root"] as? String
            ?? json["nas_root"] as? String
        let targets = roots + [writeDir].compactMap { $0 }.filter { !$0.isEmpty }

        return MonitorAccessPlan(
            configPath: configPath,
            readRoots: roots,
            writeCanaryDir: writeDir,
            suggestedRoot: commonAncestor(of: targets)
        )
    }

    private func primeAccess(plan: MonitorAccessPlan) throws -> PrimeStatus {
        var readRoots: [String] = []
        for root in plan.readRoots {
            try readDirectory(root)
            readRoots.append(root)
        }

        if let writeDir = plan.writeCanaryDir, !writeDir.isEmpty {
            try writeReadDeleteCanary(in: writeDir)
        }

        return PrimeStatus(
            ok: true,
            configPath: plan.configPath,
            readRoots: readRoots,
            writeCanaryDir: plan.writeCanaryDir,
            error: nil
        )
    }

    private func shouldRequestFolderAccess(args: [String]) -> Bool {
        args.isEmpty || args.contains("--prompt") || args.contains("--request-folder-access")
    }

    private func requestFolderAccess(for plan: MonitorAccessPlan) throws -> [URL] {
        guard Thread.isMainThread else {
            throw PrimeError("folder authorization must run on the main thread")
        }
        let panel = NSOpenPanel()
        panel.title = "Authorize NAS Access"
        panel.message = "Select the NAS folder that contains the configured iCloudPD photo roots."
        panel.prompt = "Authorize"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.canCreateDirectories = false
        if let suggestedRoot = plan.suggestedRoot {
            panel.directoryURL = URL(fileURLWithPath: suggestedRoot, isDirectory: true)
        }

        let response = panel.runModal()
        guard response == .OK, !panel.urls.isEmpty else {
            throw PrimeError("folder authorization was cancelled")
        }

        let selectedURLs = panel.urls.map { $0.standardizedFileURL }
        let requiredPaths = (plan.readRoots + [plan.writeCanaryDir].compactMap { $0 })
            .filter { !$0.isEmpty }
        let uncovered = requiredPaths.filter { required in
            !selectedURLs.contains { selected in
                path(selected.path, contains: required)
            }
        }
        guard uncovered.isEmpty else {
            throw PrimeError(
                "selected folder does not contain configured path: \(uncovered[0])"
            )
        }
        return selectedURLs
    }

    private func requestNASAuthorization(for plan: MonitorAccessPlan) throws -> NASAuthorization {
        guard Thread.isMainThread else {
            throw PrimeError("NAS authorization must run on the main thread")
        }
        let selectedURLs = try requestFolderAccess(for: plan)
        let authorization = NASAuthorization(
            plan: plan,
            scopedAccess: selectedURLs.filter { $0.startAccessingSecurityScopedResource() }
        )
        do {
            try saveFolderBookmarks(selectedURLs)
            return authorization
        } catch {
            authorization.stopAccessingSecurityScopedResources()
            throw error
        }
    }

    private func saveFolderBookmarks(_ urls: [URL]) throws {
        guard Thread.isMainThread else {
            throw PrimeError("folder bookmark saving must run on the main thread")
        }
        let bookmarks = try urls.map { url in
            try url.bookmarkData(
                options: [.withSecurityScope],
                includingResourceValuesForKeys: nil,
                relativeTo: nil
            )
        }
        let stored = StoredBookmarks(version: 1, bookmarks: bookmarks)
        let data = try PropertyListEncoder().encode(stored)
        let destination = try bookmarkStoreURL()
        try FileManager.default.createDirectory(
            at: destination.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try data.write(to: destination, options: .atomic)
        AppLogger.log("folder_bookmarks_saved", fields: [
            "count": urls.count,
            "path": destination.path,
        ])
    }

    private func startStoredFolderAccess() -> [URL] {
        loadStoredFolderAccess()
    }

    private func bookmarkStoreURL() throws -> URL {
        try appBookmarkStoreURL()
    }

    private func readDirectory(_ path: String) throws {
        _ = try FileManager.default.contentsOfDirectory(atPath: path).first
    }

    private func writeReadDeleteCanary(in directory: String) throws {
        let url = URL(fileURLWithPath: directory)
            .appendingPathComponent(".icloudpd-optimizer-app-canary-\(ProcessInfo.processInfo.processIdentifier)")
        try Data("ok".utf8).write(to: url, options: .withoutOverwriting)
        let contents = try Data(contentsOf: url)
        guard contents == Data("ok".utf8) else {
            try? FileManager.default.removeItem(at: url)
            throw PrimeError("canary readback mismatch at \(url.path)")
        }
        try FileManager.default.removeItem(at: url)
    }

    private func showResult(_ status: PrimeStatus) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { [weak self] in
                self?.showResult(status)
            }
            return
        }
        let alert = NSAlert()
        alert.messageText = status.ok ? "iCloudPD Optimizer Access Verified" : "iCloudPD Optimizer Needs Access"
        if status.ok {
            alert.informativeText = "The app can read the configured NAS paths and write a temporary canary. You can start or restart the service now."
            alert.alertStyle = .informational
        } else {
            alert.informativeText = status.error ?? "macOS denied access to the configured NAS paths."
            alert.alertStyle = .warning
        }
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func writeStatus(_ status: PrimeStatus, to path: String) {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(status)
            try data.write(to: URL(fileURLWithPath: path))
        } catch {
            fputs("failed to write status file \(path): \(error)\n", stderr)
        }
    }

    private func argumentValue(_ name: String, in args: [String]) -> String? {
        for index in args.indices {
            let argument = args[index]
            if argument == name, args.indices.contains(index + 1), !args[index + 1].isEmpty {
                return args[index + 1]
            }
            let prefix = "\(name)="
            if argument.hasPrefix(prefix) {
                let value = String(argument.dropFirst(prefix.count))
                if !value.isEmpty {
                    return value
                }
            }
        }
        return nil
    }

    private func resolveDashboardConfigPath() -> DashboardConfigResolution? {
        if let path = bundledConfigPath(), !path.isEmpty {
            return DashboardConfigResolution(path: path, source: "bundle")
        }
        if let path = launchAgentConfigPath(), !path.isEmpty {
            return DashboardConfigResolution(path: path, source: "launch_agent")
        }
        if let path = defaultConfigPath(), !path.isEmpty {
            return DashboardConfigResolution(path: path, source: "default")
        }
        return nil
    }

    private func bundledConfigPath() -> String? {
        guard let url = Bundle.main.resourceURL?.appendingPathComponent("monitor-config-path") else {
            return nil
        }
        return try? String(contentsOf: url, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func launchAgentConfigPath() -> String? {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.icloudpd-optimizer.monitor.plist")
        guard
            let data = try? Data(contentsOf: url),
            let plist = try? PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            ),
            let dictionary = plist as? [String: Any],
            let arguments = dictionary["ProgramArguments"] as? [String]
        else {
            return nil
        }
        return argumentValue("--config", in: arguments)
    }

    private func defaultConfigPath() -> String? {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/icloudpd-optimizer/monitor.json")
        return FileManager.default.fileExists(atPath: url.path) ? url.path : nil
    }

    private func uniquePaths(_ paths: [String?]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for path in paths.compactMap({ $0 }).filter({ !$0.isEmpty }) {
            if seen.insert(path).inserted {
                result.append(path)
            }
        }
        return result
    }

    private func commonAncestor(of paths: [String]) -> String? {
        let components = paths
            .filter { !$0.isEmpty }
            .map { URL(fileURLWithPath: $0).standardizedFileURL.pathComponents }
        guard var common = components.first, !common.isEmpty else {
            return nil
        }
        for pathComponents in components.dropFirst() {
            common = Array(zip(common, pathComponents).prefix { $0 == $1 }.map { $0.0 })
            if common.isEmpty {
                return nil
            }
        }
        return NSString.path(withComponents: common)
    }

    private func path(_ ancestor: String, contains child: String) -> Bool {
        let ancestorPath = URL(fileURLWithPath: ancestor).standardizedFileURL.path
        let childPath = URL(fileURLWithPath: child).standardizedFileURL.path
        return childPath == ancestorPath || childPath.hasPrefix(ancestorPath + "/")
    }
}

struct PrimeError: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}

private let dashboardProcessSelfTestBytes = 256 * 1024

private func emitDashboardProcessSelfTestOutputAndExit() -> Never {
    FileHandle.standardOutput.write(Data(repeating: 111, count: dashboardProcessSelfTestBytes))
    FileHandle.standardError.write(Data(repeating: 101, count: dashboardProcessSelfTestBytes))
    exit(0)
}

private func dashboardProcessCaptureSelfTest() -> Bool {
    guard let result = try? runCapturedProcess(
        executableURL: URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL,
        arguments: ["--dashboard-process-output-self-test"]
    ) else {
        return false
    }
    return result.status == 0
        && result.stdout.utf8.count == dashboardProcessSelfTestBytes
        && result.stderr.utf8.count == dashboardProcessSelfTestBytes
}

private func runDashboardMetricsSelfTestAndExit() -> Never {
    let now: TimeInterval = 1_000_000
    let lines = [
        "{\"at_unix_seconds\":999940,\"event\":\"upload_finished\",\"fields\":{\"asset_id\":\"upload-a\",\"uploaded\":true}}",
        "{\"at_unix_seconds\":999600,\"event\":\"upload_finished\",\"fields\":{\"asset_id\":\"upload-b\",\"uploaded\":true}}",
        "{\"at_unix_seconds\":1000060,\"event\":\"upload_finished\",\"fields\":{\"uploaded\":true}}",
        "{\"at_unix_seconds\":999099,\"event\":\"upload_finished\",\"fields\":{\"uploaded\":true}}",
        "{\"at_unix_seconds\":999880,\"event\":\"delete_batch_finished\",\"fields\":{\"recorded_deletes\":3,\"bytes_saved\":12}}",
        "{\"at_unix_seconds\":999900,\"event\":\"conversion_finished\",\"fields\":{\"converted\":true}}",
        "{\"at_unix_seconds\":999900,\"event\":\"heic_verify_finished\",\"fields\":{\"asset_id\":\"quality-a\",\"verified\":false}}",
        "{\"at_unix_seconds\":999850,\"event\":\"heic_verify_finished\",\"fields\":{\"asset_id\":\"quality-a\",\"verified\":false}}",
        "{\"at_unix_seconds\":999800,\"event\":\"upload_finished\",\"fields\":{\"asset_id\":\"upload-blocked\",\"uploaded\":false,\"error\":\"blocked\"}}",
        "{\"at_unix_seconds\":999780,\"event\":\"local_mirror_failed\",\"fields\":{\"asset_id\":\"mirror-a\",\"error\":\"blocked\"}}",
        "{\"at_unix_seconds\":999760,\"event\":\"local_mirror_failed\",\"fields\":{\"asset_id\":\"mirror-a\",\"error\":\"blocked\"}}",
        "{\"at_unix_seconds\":999950,\"event\":\"monitor_failed\",\"fields\":{\"error\":\"blocked\"}}",
        "{\"at_unix_seconds\":999970,\"event\":\"rolling_lifecycle_worker_asset_finished\",\"fields\":{\"conversions_completed_delta\":2,\"uploads_completed_delta\":4,\"originals_deleted_delta\":1,\"failures_delta\":1}}",
        "{\"at_unix_seconds\":999650,\"event\":\"rolling_lifecycle_worker_asset_finished\",\"fields\":{\"conversions_completed_delta\":3,\"uploads_completed_delta\":5,\"originals_deleted_delta\":2,\"failures_delta\":0}}",
    ]
    let metrics = DashboardMetricsParser.liveThroughputMetrics(lines.joined(separator: "\n"), now: now)
    let displayedThroughput = Dictionary(
        uniqueKeysWithValues: throughputStats(from: metrics).map { ($0.id, $0) }
    )
    let partialCoverage = DashboardMetricsParser.liveThroughputMetrics(
        [
            "{\"at_unix_seconds\":999940,\"event\":\"upload_finished\",\"fields\":{\"uploaded\":true}}",
            "{\"at_unix_seconds\":999970,\"event\":\"upload_finished\",\"fields\":{\"uploaded\":true}}",
        ].joined(separator: "\n"),
        now: now
    )
    let productionFailureLines = [
        "{\"event\":\"original_asset_resolve_batch_finished\",\"scan_started_unix_seconds\":999700,\"at_unix_seconds\":999800,\"fields\":{\"targets\":3,\"resolved\":1,\"unresolved\":2,\"unresolved_asset_ids\":[\"resolver-a\",\"resolver-b\"],\"wall_time_seconds\":4,\"batch_limit\":4}}",
        "{\"event\":\"original_asset_resolve_batch_finished\",\"scan_started_unix_seconds\":999700,\"at_unix_seconds\":999850,\"fields\":{\"targets\":1,\"resolved\":0,\"unresolved\":1,\"unresolved_asset_ids\":[\"resolver-a\"],\"wall_time_seconds\":3,\"batch_limit\":4}}",
        "{\"event\":\"original_asset_resolve_batch_finished\",\"scan_started_unix_seconds\":999700,\"at_unix_seconds\":999875,\"fields\":{\"targets\":4,\"resolved\":0,\"unresolved\":4,\"unresolved_asset_ids\":[],\"wall_time_seconds\":2,\"batch_limit\":4,\"error\":\"resolver unavailable\"}}",
        "{\"event\":\"discovery_finished\",\"scan_started_unix_seconds\":999700,\"at_unix_seconds\":999900,\"fields\":{\"raw_files_seen\":3991,\"skipped_known\":3991,\"failures\":0}}",
        "{\"event\":\"delete_batch_commit_failed\",\"scan_started_unix_seconds\":999700,\"at_unix_seconds\":999910,\"fields\":{\"failure_id\":\"999700:delete_batch_commit_failed:1\",\"error\":\"commit failed\"}}",
        "{\"event\":\"monitor_failed\",\"at_unix_seconds\":999911,\"fields\":{\"failure_id\":\"999700:delete_batch_commit_failed:1\",\"scan_started_unix_seconds\":999700,\"error\":\"commit failed\"}}",
        "{\"event\":\"delete_batch_commit_failed\",\"scan_started_unix_seconds\":999700,\"at_unix_seconds\":999920,\"fields\":{\"failure_id\":\"999700:delete_batch_commit_failed:2\",\"error\":\"independent commit failed\"}}",
        "{\"event\":\"monitor_failed\",\"at_unix_seconds\":999921,\"fields\":{\"failure_id\":\"999700:delete_batch_commit_failed:2\",\"scan_started_unix_seconds\":999700,\"error\":\"independent commit failed\"}}",
        "{\"event\":\"monitor_failed\",\"at_unix_seconds\":999950,\"fields\":{\"error\":\"failed to canonicalize monitor root\"}}",
    ]
    let productionFailures = DashboardMetricsParser.liveThroughputMetrics(
        productionFailureLines.joined(separator: "\n"),
        now: now
    )
    let queueJSON = """
    {
      "configured_mode":"rolling",
      "rolling_lifecycle":true,
      "jobs":2,
      "rolling_worker_count":2,
      "cpu_stage_slots":2,
      "convert_stage_slots":1,
      "max_lifecycle_per_scan":100,
      "max_conversions_per_scan":100,
      "state_counts":{"deleted":2301,"no_action":52,"needs_review":49,"failed":3997,"nas_verified":1},
      "queue_counts":{"active_lifecycle":2},
      "failure_counts":{"blocked_original_asset_resolve":3991,"blocked_visual_content":4,"failed_other":2},
      "verified_metrics":{
        "total_records":6400,
        "state_counts":{"deleted":2301,"no_action":52,"needs_review":49,"failed":3997,"nas_verified":1},
        "terminal_records":2402,
        "no_action_records":52,
        "needs_review_records":49,
        "failed_records":3997,
        "pending_records":1,
        "uploaded_replacements":2400,
        "uploaded_heic_bytes":15482906008,
        "uploaded_size_metrics_complete":true,
        "uploaded_records_missing_size_proofs":0,
        "deleted_originals":2301,
        "deleted_raw_bytes":79144954592,
        "verified_bytes_saved":63662048584,
        "deleted_size_metrics_complete":true,
        "deleted_records_missing_size_proofs":0
      },
      "active_lifecycle":[],
      "worker_slots":[]
    }
    """
    let decodedQueue = try? JSONDecoder().decode(MonitorQueuePayload.self, from: Data(queueJSON.utf8))
    let partialQueueJSON = queueJSON
        .replacingOccurrences(of: "\"deleted_size_metrics_complete\":true", with: "\"deleted_size_metrics_complete\":false")
        .replacingOccurrences(of: "\"deleted_records_missing_size_proofs\":0", with: "\"deleted_records_missing_size_proofs\":3")
    let overflowQueueJSON = queueJSON
        .replacingOccurrences(of: "\"deleted_size_metrics_complete\":true", with: "\"deleted_size_metrics_complete\":false")
    let unavailableQueueJSON = partialQueueJSON
        .replacingOccurrences(of: "\"deleted_originals\":2301", with: "\"deleted_originals\":3")
    let partialQueue = try? JSONDecoder().decode(MonitorQueuePayload.self, from: Data(partialQueueJSON.utf8))
    let overflowQueue = try? JSONDecoder().decode(MonitorQueuePayload.self, from: Data(overflowQueueJSON.utf8))
    let unavailableQueue = try? JSONDecoder().decode(MonitorQueuePayload.self, from: Data(unavailableQueueJSON.utf8))
    let summaryMetrics = operatorSummaryMetrics(
        statsPayload: nil,
        queuePayload: decodedQueue,
        logs: DashboardLogState(raw: lines.joined(separator: "\n"), events: [], workerActivities: [:], throughput: metrics)
    )
    let summaryByTitle = Dictionary(uniqueKeysWithValues: summaryMetrics.map { ($0.title, $0) })
    let partialSummary = operatorSummaryMetrics(statsPayload: nil, queuePayload: partialQueue, logs: nil)
    let overflowSummary = operatorSummaryMetrics(statsPayload: nil, queuePayload: overflowQueue, logs: nil)
    let unavailableSummary = operatorSummaryMetrics(statsPayload: nil, queuePayload: unavailableQueue, logs: nil)
    let partialSpaceSaved = partialSummary.first { $0.title == "Space saved (partial)" }
    let overflowSpaceSaved = overflowSummary.first { $0.title == "Space saved unavailable" }
    let unavailableSpaceSaved = unavailableSummary.first { $0.title == "Space saved unavailable" }
    let queue = MonitorQueuePayload(
        configuredMode: "rolling",
        rollingLifecycle: true,
        jobs: 2,
        rollingWorkerCount: nil,
        cpuStageSlots: 2,
        convertStageSlots: 1,
        maxLifecyclePerScan: 100,
        maxConversionsPerScan: 100,
        stateCounts: [:],
        queueCounts: [
            "active_lifecycle": 2,
            "resolve_original_assets": 90,
            "convert_heic": 50,
        ],
        failureCounts: [:],
        verifiedMetrics: VerifiedMetricsPayload(
            totalRecords: 2,
            stateCounts: [:],
            uploadedReplacements: 0,
            uploadedHeicBytes: 0,
            uploadedSizeMetricsComplete: true,
            uploadedRecordsMissingSizeProofs: 0,
            deletedOriginals: 0,
            deletedRawBytes: 0,
            verifiedBytesSaved: 0,
            deletedSizeMetricsComplete: true,
            deletedRecordsMissingSizeProofs: 0
        ),
        activeLifecycle: [
            QueueAssetPayload(
                assetId: "raw-a",
                state: "nas_verified",
                nextStage: "convert_heic",
                rawSizeBytes: 10
            ),
            QueueAssetPayload(
                assetId: "raw-b",
                state: "conversion_verified",
                nextStage: "upload_verified_heics",
                rawSizeBytes: 12
            ),
        ],
        workerSlots: []
    )
    let stageCounts = activeStageCounts(queue)
    let bottleneck = bottleneckStage(queue)
    let waitingActivity = WorkerActivity(
        workerId: 1,
        assetId: "raw-a",
        stage: "convert_heic",
        detail: "waiting for CPU slot",
        updatedAt: Date(timeIntervalSince1970: now),
        finished: false
    )
    let activeActivity = WorkerActivity(
        workerId: 2,
        assetId: "raw-b",
        stage: "upload_verified_heics",
        detail: "started",
        updatedAt: Date(timeIntervalSince1970: now),
        finished: false
    )
    let checks: [(String, Bool)] = [
        ("uploads5m", metrics.uploads5m == 1),
        ("uploads15m", metrics.uploads15m == 2),
        ("deletes15m", metrics.deletes15m == 3),
        ("conversions15m", metrics.conversions15m == 1),
        ("blockedAssets15mDeduplicatesAttempts", metrics.blockedAssets15m == 3),
        ("failureAttempts15m", metrics.failureAttempts15m == 6),
        ("assetlessFailureAttempts15m", metrics.assetlessFailureAttempts15m == 1),
        ("productionResolverFailuresAreDistinct", productionFailures.blockedAssets15m == 2),
        ("productionResolverRetriesIncrementAttempts", productionFailures.failureAttempts15m == 7),
        ("productionAssetlessFailuresRemainAttempts", productionFailures.assetlessFailureAttempts15m == 4),
        ("skippedKnownDoesNotBecomeBacklog", productionFailures.blockedAssets15m != 3991),
        ("bytesSaved15m", metrics.bytesSaved15m == 12),
        ("queueDecodesDurableUploads", decodedQueue?.verifiedMetrics.uploadedReplacements == 2400),
        ("queueDecodesDurableDeletes", decodedQueue?.verifiedMetrics.deletedOriginals == 2301),
        ("queueDecodesDurableBytesSaved", decodedQueue?.verifiedMetrics.verifiedBytesSaved == 63_662_048_584),
        ("queueDecodesDeletedSizeCompleteness", decodedQueue?.verifiedMetrics.deletedSizeMetricsComplete == true),
        ("queueDecodesDeletedMissingProofCount", decodedQueue?.verifiedMetrics.deletedRecordsMissingSizeProofs == 0),
        ("partialSpaceSavedIsLabeled", partialSpaceSaved?.value == DashboardFormat.bytes(63_662_048_584)),
        ("partialSpaceSavedShowsExactMissingCount", partialSpaceSaved?.detail == "3 deleted records missing size proofs"),
        ("overflowSpaceSavedIsUnavailable", overflowSpaceSaved?.value == "--"),
        ("overflowSpaceSavedAvoidsMissingProofClaim", overflowSpaceSaved?.detail == "lifetime size metric unavailable or out of supported range"),
        ("unavailableSpaceSavedIsLabeled", unavailableSpaceSaved?.value == "--"),
        ("unavailableSpaceSavedShowsExactMissingCount", unavailableSpaceSaved?.detail == "3 deleted records missing size proofs"),
        ("summaryPanelSeparatesTimeRanges", operatorSummaryPanelTitle == "Lifetime totals and recent activity"),
        ("summaryUsesDurableUploads", summaryByTitle["Uploaded total"]?.value == "2400"),
        ("summaryUsesDurableDeletes", summaryByTitle["Deleted total"]?.value == "2301"),
        ("summarySeparatesNoActionTerminals", summaryByTitle["No action total"]?.value == "52"),
        ("summarySeparatesNeedsReviewTerminals", summaryByTitle["Needs review total"]?.value == "49"),
        ("summaryUsesDurableBytesSaved", summaryByTitle["Space saved total"]?.value == DashboardFormat.bytes(63_662_048_584)),
        ("summaryLabelsRecentBlockedAssets", summaryByTitle["Blocked assets (15m)"]?.value == "3"),
        ("summaryReportsAttemptsSeparately", summaryByTitle["Blocked assets (15m)"]?.detail == "6 retry/failure attempts; 1 without asset ID"),
        ("resolverFailureBucketLabel", DashboardFormat.failureBucket("blocked_original_asset_resolve") == "unmatched iCloud originals"),
        ("partialCoverageRateUsesObservedWindow", partialCoverage.hourlyRate(2) == "120.0/hr"),
        ("activeStageCountConvert", stageCounts["convert_heic"] == 1),
        ("activeStageCountUpload", stageCounts["upload_verified_heics"] == 1),
        ("activeStageCountIgnoresBacklog", stageCounts["resolve_original_assets"] == nil),
        ("activeBottleneckUsesActiveBatch", bottleneck.count == 1),
        ("throughputShowsActualUploads", displayedThroughput["uploaded"]?.value == "2"),
        ("waitingWorkerIsNotActive", workerDisplayState(waitingActivity, now: Date(timeIntervalSince1970: now)) == .waiting),
        ("workingWorkerIsActive", workerDisplayState(activeActivity, now: Date(timeIntervalSince1970: now)) == .active),
        ("missingWorkerIsIdle", workerDisplayState(nil, now: Date(timeIntervalSince1970: now)) == .idle),
        ("processCaptureDrainsLargeOutput", dashboardProcessCaptureSelfTest()),
    ]
    let failures = checks.filter { !$0.1 }.map(\.0)
    if failures.isEmpty {
        print("dashboard metrics self-test ok")
        exit(0)
    }
    let message = "dashboard metrics self-test failed: \(failures.joined(separator: ", "))\n"
    FileHandle.standardError.write(Data(message.utf8))
    exit(2)
}

let launchArgs = Array(CommandLine.arguments.dropFirst())
if launchArgs == ["--dashboard-process-output-self-test"] {
    emitDashboardProcessSelfTestOutputAndExit()
}
if launchArgs == ["--dashboard-metrics-self-test"] {
    runDashboardMetricsSelfTestAndExit()
}
if shouldProxyLaunchArguments(launchArgs) {
    runBundledHelperAndExit(args: launchArgs)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
