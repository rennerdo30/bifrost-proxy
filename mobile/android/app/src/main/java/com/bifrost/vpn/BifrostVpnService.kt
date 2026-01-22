// BifrostVpnService.kt
// Bifrost VPN Android VpnService Implementation
//
// This implements the VpnService for Android VPN functionality.
// It handles the low-level packet tunneling for the Bifrost VPN connection.

package com.bifrost.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class BifrostVpnService : VpnService() {

    companion object {
        private const val TAG = "BifrostVpnService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "bifrost_vpn_channel"

        // Action constants
        const val ACTION_START = "com.bifrost.vpn.START"
        const val ACTION_STOP = "com.bifrost.vpn.STOP"

        // Configuration keys
        const val EXTRA_SERVER_ADDRESS = "server_address"
        const val EXTRA_SERVER_PORT = "server_port"
        const val EXTRA_TUNNEL_ADDRESS = "tunnel_address"
        const val EXTRA_DNS_SERVERS = "dns_servers"
        const val EXTRA_MTU = "mtu"
    }

    // VPN interface
    private var vpnInterface: ParcelFileDescriptor? = null

    // Tunnel threads
    private var tunnelThread: Thread? = null
    private var readThread: Thread? = null

    // State
    private val isRunning = AtomicBoolean(false)

    // Statistics
    @Volatile private var bytesIn: Long = 0
    @Volatile private var bytesOut: Long = 0

    // Configuration
    private var serverAddress: String = ""
    private var serverPort: Int = 51820
    private var tunnelAddress: String = "10.0.0.2"
    private var mtu: Int = 1420

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                // Extract configuration
                serverAddress = intent.getStringExtra(EXTRA_SERVER_ADDRESS) ?: ""
                serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 51820)
                tunnelAddress = intent.getStringExtra(EXTRA_TUNNEL_ADDRESS) ?: "10.0.0.2"
                mtu = intent.getIntExtra(EXTRA_MTU, 1420)

                if (serverAddress.isEmpty()) {
                    Log.e(TAG, "No server address provided")
                    stopSelf()
                    return START_NOT_STICKY
                }

                startVpn()
            }
            ACTION_STOP -> {
                stopVpn()
            }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startVpn() {
        if (isRunning.getAndSet(true)) {
            Log.w(TAG, "VPN already running")
            return
        }

        Log.i(TAG, "Starting Bifrost VPN to $serverAddress:$serverPort")

        // Start foreground service
        startForeground(NOTIFICATION_ID, createNotification("Connecting..."))

        // Configure VPN interface
        try {
            val builder = Builder()
                .setSession("Bifrost VPN")
                .setMtu(mtu)
                .addAddress(tunnelAddress, 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setBlocking(true)

            // Exclude the Bifrost app itself from VPN
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "Could not exclude self from VPN: ${e.message}")
            }

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopVpn()
                return
            }

            Log.i(TAG, "VPN interface established")
            updateNotification("Connected to $serverAddress")

            // Start tunnel threads
            startTunnelThreads()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}")
            stopVpn()
        }
    }

    private fun stopVpn() {
        Log.i(TAG, "Stopping Bifrost VPN")

        isRunning.set(false)

        // Stop threads
        tunnelThread?.interrupt()
        readThread?.interrupt()
        tunnelThread = null
        readThread = null

        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing VPN interface: ${e.message}")
        }
        vpnInterface = null

        // Stop foreground
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startTunnelThreads() {
        val vpnFd = vpnInterface ?: return

        // Thread for reading from TUN and sending to server
        readThread = Thread {
            val socket = DatagramSocket()
            socket.connect(InetSocketAddress(serverAddress, serverPort))

            val input = FileInputStream(vpnFd.fileDescriptor)
            val packet = ByteBuffer.allocate(mtu)

            try {
                while (isRunning.get()) {
                    // Read from TUN interface
                    val length = input.read(packet.array())
                    if (length > 0) {
                        packet.limit(length)

                        // Send to server
                        val datagram = DatagramPacket(
                            packet.array(),
                            length,
                            InetSocketAddress(serverAddress, serverPort)
                        )
                        socket.send(datagram)

                        bytesOut += length
                        packet.clear()
                    }
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e(TAG, "Read thread error: ${e.message}")
                }
            } finally {
                socket.close()
            }
        }.apply {
            name = "BifrostVPN-Read"
            start()
        }

        // Thread for receiving from server and writing to TUN
        tunnelThread = Thread {
            val socket = DatagramSocket()
            socket.connect(InetSocketAddress(serverAddress, serverPort))

            val output = FileOutputStream(vpnFd.fileDescriptor)
            val buffer = ByteArray(mtu)
            val packet = DatagramPacket(buffer, buffer.size)

            try {
                while (isRunning.get()) {
                    // Receive from server
                    socket.receive(packet)

                    if (packet.length > 0) {
                        // Write to TUN interface
                        output.write(packet.data, 0, packet.length)

                        bytesIn += packet.length
                    }
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e(TAG, "Tunnel thread error: ${e.message}")
                }
            } finally {
                socket.close()
            }
        }.apply {
            name = "BifrostVPN-Tunnel"
            start()
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Bifrost VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Bifrost VPN connection status"
                setShowBadge(false)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(status: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
            .setContentTitle("Bifrost VPN")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, createNotification(status))
    }

    // Binder for statistics
    inner class LocalBinder : android.os.Binder() {
        fun getService(): BifrostVpnService = this@BifrostVpnService
    }

    private val binder = LocalBinder()

    override fun onBind(intent: Intent?): android.os.IBinder {
        return binder
    }

    // Public methods for statistics
    fun getBytesIn(): Long = bytesIn
    fun getBytesOut(): Long = bytesOut
    fun isVpnRunning(): Boolean = isRunning.get()
}
