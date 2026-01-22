// PacketTunnelProvider.swift
// Bifrost VPN iOS Network Extension
//
// This implements the NEPacketTunnelProvider for iOS VPN functionality.
// It handles the low-level packet tunneling for the Bifrost VPN connection.

import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - Properties

    private let log = OSLog(subsystem: "com.bifrost.vpn", category: "tunnel")
    private var pendingStartCompletion: ((Error?) -> Void)?
    private var session: NWUDPSession?
    private var tunnelAddress: String?
    private var serverAddress: String?
    private var mtu: Int = 1420

    // MARK: - Lifecycle

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log(.info, log: log, "Starting Bifrost VPN tunnel")

        pendingStartCompletion = completionHandler

        // Get configuration from protocolConfiguration
        guard let tunnelProviderProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = tunnelProviderProtocol.providerConfiguration else {
            os_log(.error, log: log, "Missing tunnel configuration")
            completionHandler(BifrostError.missingConfiguration)
            return
        }

        // Extract configuration
        serverAddress = providerConfiguration["serverAddress"] as? String
        tunnelAddress = providerConfiguration["tunnelAddress"] as? String ?? "10.0.0.2"
        mtu = providerConfiguration["mtu"] as? Int ?? 1420

        guard let server = serverAddress else {
            os_log(.error, log: log, "Missing server address")
            completionHandler(BifrostError.missingServerAddress)
            return
        }

        // Configure tunnel settings
        configureTunnelNetworkSettings { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                os_log(.error, log: self.log, "Failed to configure tunnel: %{public}@", error.localizedDescription)
                completionHandler(error)
                return
            }

            // Start the tunnel connection
            self.startConnection(to: server) { error in
                if let error = error {
                    os_log(.error, log: self.log, "Failed to start connection: %{public}@", error.localizedDescription)
                } else {
                    os_log(.info, log: self.log, "Tunnel started successfully")
                }
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log(.info, log: log, "Stopping tunnel with reason: %{public}d", reason.rawValue)

        // Clean up session
        session?.cancel()
        session = nil

        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle messages from the main app
        guard let message = try? JSONDecoder().decode(AppMessage.self, from: messageData) else {
            completionHandler?(nil)
            return
        }

        os_log(.debug, log: log, "Received app message: %{public}@", message.type)

        switch message.type {
        case "getStatus":
            let status = TunnelStatus(
                connected: session != nil,
                serverAddress: serverAddress ?? "",
                tunnelAddress: tunnelAddress ?? "",
                bytesIn: 0,
                bytesOut: 0
            )
            if let data = try? JSONEncoder().encode(status) {
                completionHandler?(data)
            } else {
                completionHandler?(nil)
            }

        case "disconnect":
            cancelTunnelWithError(nil)
            completionHandler?(nil)

        default:
            completionHandler?(nil)
        }
    }

    // MARK: - Private Methods

    private func configureTunnelNetworkSettings(completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverAddress ?? "0.0.0.0")

        // Configure IPv4
        let ipv4Settings = NEIPv4Settings(addresses: [tunnelAddress ?? "10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4Settings

        // Configure DNS
        let dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dnsSettings.matchDomains = [""] // Match all domains
        settings.dnsSettings = dnsSettings

        // Configure MTU
        settings.mtu = NSNumber(value: mtu)

        // Apply settings
        setTunnelNetworkSettings(settings, completionHandler: completionHandler)
    }

    private func startConnection(to server: String, completionHandler: @escaping (Error?) -> Void) {
        // Parse server address
        let components = server.split(separator: ":")
        guard components.count == 2,
              let port = Int(components[1]) else {
            completionHandler(BifrostError.invalidServerAddress)
            return
        }

        let host = String(components[0])
        let endpoint = NWHostEndpoint(hostname: host, port: String(port))

        // Create UDP session for WireGuard-like protocol
        session = createUDPSession(to: endpoint, from: nil)

        // Monitor session state
        session?.setReadHandler({ [weak self] packets, error in
            guard let self = self else { return }

            if let error = error {
                os_log(.error, log: self.log, "Read error: %{public}@", error.localizedDescription)
                return
            }

            // Handle incoming packets
            if let packets = packets {
                for packet in packets {
                    self.handleIncomingPacket(packet)
                }
            }
        }, maxDatagrams: 100)

        // Start reading from the TUN interface
        startReadingPackets()

        completionHandler(nil)
    }

    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }

            // Forward packets to the server
            for (index, packet) in packets.enumerated() {
                self.sendPacket(packet, protocol: protocols[index])
            }

            // Continue reading
            self.startReadingPackets()
        }
    }

    private func sendPacket(_ packet: Data, protocol protocolNumber: NSNumber) {
        guard let session = session else { return }

        // Wrap packet and send to server
        session.writeDatagram(packet) { error in
            if let error = error {
                os_log(.error, log: self.log, "Write error: %{public}@", error.localizedDescription)
            }
        }
    }

    private func handleIncomingPacket(_ packet: Data) {
        // Determine protocol (IPv4 or IPv6)
        guard packet.count > 0 else { return }

        let protocolNumber: NSNumber
        let version = packet[0] >> 4

        switch version {
        case 4:
            protocolNumber = NSNumber(value: AF_INET)
        case 6:
            protocolNumber = NSNumber(value: AF_INET6)
        default:
            return
        }

        // Write packet to TUN interface
        packetFlow.writePackets([packet], withProtocols: [protocolNumber])
    }
}

// MARK: - Error Types

enum BifrostError: Error, LocalizedError {
    case missingConfiguration
    case missingServerAddress
    case invalidServerAddress
    case connectionFailed

    var errorDescription: String? {
        switch self {
        case .missingConfiguration:
            return "Missing tunnel configuration"
        case .missingServerAddress:
            return "Missing server address in configuration"
        case .invalidServerAddress:
            return "Invalid server address format"
        case .connectionFailed:
            return "Failed to establish connection"
        }
    }
}

// MARK: - Message Types

struct AppMessage: Codable {
    let type: String
    let data: [String: String]?
}

struct TunnelStatus: Codable {
    let connected: Bool
    let serverAddress: String
    let tunnelAddress: String
    let bytesIn: Int64
    let bytesOut: Int64
}
