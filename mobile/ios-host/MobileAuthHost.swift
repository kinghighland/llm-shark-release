import Foundation

public final class MobileAuthHost {
    public protocol FfiApi {
        func mobileQrPublicKeyPem() -> String
        func validateLicense(requestJson: String) -> String
        func buildPolicy(requestJson: String) -> String
    }

    public struct Result {
        public let ok: Bool
        public let verifyResponseJson: String
        public let policyResponseJson: String?
    }

    private struct HostState: Codable {
        var usedDay: String
        var usedToday: Int
        var lastTrustedTimestamp: String?
        var seenNonces: [String]
    }

    private let defaults: UserDefaults
    private let key = "llmshark_mobile_auth_v1"
    private let ffi: FfiApi

    public init(ffi: FfiApi, defaults: UserDefaults = .standard) {
        self.ffi = ffi
        self.defaults = defaults
    }

    public func importPayloadAndBuildPolicy(payloadJson: String) -> Result {
        let nowUtc = ISO8601DateFormatter().string(from: Date())
        let today = Self.localDayString()
        let state = loadState()
        let usedToday = state.usedDay == today ? state.usedToday : 0

        let req: [String: Any?] = [
            "payload_json": payloadJson,
            "public_key_pem": ffi.mobileQrPublicKeyPem(),
            "now_utc": nowUtc,
            "used_today": usedToday,
            "seen_nonces": state.seenNonces,
            "last_trusted_timestamp": state.lastTrustedTimestamp
        ]

        let verifyOut = ffi.validateLicense(requestJson: Self.toJson(req))
        guard
            let verifyRoot = Self.parseJsonObject(verifyOut),
            (verifyRoot["ok"] as? Bool) == true,
            let data = verifyRoot["data"] as? [String: Any]
        else {
            return Result(ok: false, verifyResponseJson: verifyOut, policyResponseJson: nil)
        }

        let nonce = (data["nonce"] as? String) ?? ""
        var newSeen = state.seenNonces
        if !nonce.isEmpty, !newSeen.contains(nonce) {
            newSeen.append(nonce)
        }
        if newSeen.count > 256 {
            newSeen = Array(newSeen.suffix(256))
        }

        saveState(
            HostState(
                usedDay: today,
                usedToday: usedToday,
                lastTrustedTimestamp: nowUtc,
                seenNonces: newSeen
            )
        )

        let policyReq: [String: Any] = [
            "plan_tier": (data["plan_tier"] as? String) ?? "",
            "topn_limit": (data["topn_limit"] as? Int) ?? 0,
            "daily_analysis_limit": (data["daily_analysis_limit"] as? Int) ?? 0,
            "used_today": usedToday
        ]
        let policyOut = ffi.buildPolicy(requestJson: Self.toJson(policyReq))
        return Result(ok: true, verifyResponseJson: verifyOut, policyResponseJson: policyOut)
    }

    public func onAnalyzeConsumedOne() {
        let today = Self.localDayString()
        var state = loadState()
        if state.usedDay != today {
            state.usedDay = today
            state.usedToday = 0
        }
        state.usedToday += 1
        saveState(state)
    }

    private func loadState() -> HostState {
        guard let data = defaults.data(forKey: key) else {
            return HostState(usedDay: "", usedToday: 0, lastTrustedTimestamp: nil, seenNonces: [])
        }
        return (try? JSONDecoder().decode(HostState.self, from: data))
            ?? HostState(usedDay: "", usedToday: 0, lastTrustedTimestamp: nil, seenNonces: [])
    }

    private func saveState(_ state: HostState) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        defaults.set(data, forKey: key)
    }

    private static func localDayString() -> String {
        let cal = Calendar.current
        let c = cal.dateComponents([.year, .month, .day], from: Date())
        let y = c.year ?? 1970
        let m = c.month ?? 1
        let d = c.day ?? 1
        return String(format: "%04d-%02d-%02d", y, m, d)
    }

    private static func toJson(_ value: Any) -> String {
        let data = try? JSONSerialization.data(withJSONObject: value, options: [])
        return data.flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }

    private static func parseJsonObject(_ json: String) -> [String: Any]? {
        guard let data = json.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String: Any]
    }
}
