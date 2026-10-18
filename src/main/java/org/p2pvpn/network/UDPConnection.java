/*
    Copyright 2008, 2009 Wolfgang Ginolas

    This file is part of P2PVPN.

    P2PVPN is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Foobar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
*/

package org.p2pvpn.network;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.p2pvpn.network.bandwidth.MeasureBandwidth;
import org.p2pvpn.tools.CryptoUtils;
import org.p2pvpn.tools.SocketAddrStr;

/**
 * This is the lowest layer in the P2PVPN network. It encrypts packets and
 * sends and receives them using UDP.
 *
 * In contrast to a TCP stream, UDP is unreliable: datagrams may be lost,
 * duplicated or reordered. Sending the VPN traffic over UDP instead of TCP
 * avoids the "TCP over TCP" problem (a loss on the underlying link triggers
 * retransmissions on both the tunnel and the tunnelled connection, which
 * amplifies the loss and lets the congestion window of the tunnelled
 * connection collapse). The tunnel therefore treats the payload as
 * best-effort datagrams: the tunnelled IP/TCP stack is responsible for
 * retransmissions.
 *
 * The encryption is applied per datagram (a fresh random IV is used for every
 * packet) so that lost packets cannot corrupt the following ones. The
 * handshake packets are retransmitted until the peer proves that it received
 * our key part (by sending encrypted data back) and a sequence number is used
 * to drop duplicates.
 *
 * @author Wolfgang Ginolas
 */
public class UDPConnection {

	public static final int DEFAULT_MAX_QUEUE = 10;
	public static final boolean DEFAULT_TCP_FLUSH = false;

	/** the maximum size of a (plain) packet we accept/send */
	private static final int MAX_PACKET_SIZE = 10 * 1024;

	private static final double BUCKET_TIME = 0.5;
	private static final int BUCKET_LEN = 10;

	private static final int IV_LENGTH = 16;

	/** first byte of every tunnel packet, used to distinguish it from other traffic */
	static final byte MAGIC = 0x50;					// 'P'
	/** the payload is a handshake packet, encrypted with the network key */
	static final byte TYPE_HANDSHAKE = 1;
	/** the payload is a VPN data packet, encrypted with the peer key */
	static final byte TYPE_DATA = 2;

	/** sub type of a handshake packet: the access invitation */
	static final byte HANDSHAKE_ACCESS = 1;
	/** sub type of a handshake packet: the encrypted key part */
	static final byte HANDSHAKE_KEY = 2;

	/** how often handshake packets are resent */
	private static final long RETRANSMIT_MS = 1000;
	/** give up resending handshake packets after this time */
	private static final long HANDSHAKE_MAX_MS = 60 * 1000;

	private static final SecureRandom RANDOM = CryptoUtils.getSecureRandom();

	private MeasureBandwidth bwIn, bwOut;		// the currently used bandwidth

	private final ConnectionManager connectionManager;
	private final DatagramSocket socket;		// the shared UDP socket
	private final InetSocketAddress peer;		// the remote address

	private P2PConnection listener;				// the upper network layer

	private final SecretKey networkKey;			// the network wide key (handshake)
	private final Cipher netEncOut, netEncIn;

	private volatile SecretKey peerKey;			// the per peer key (data)
	private Cipher peerEncOut, peerEncIn;

	private byte[] handshakeAccess;				// the last access packet we sent
	private byte[] handshakeKey;				// the last key packet we sent

	private int sendSeq;						// send sequence number for data packets
	private int lastSeq;						// last received data sequence number
	private boolean gotData;					// did we receive any (decryptable) data?
	private boolean gotSeq;						// is lastSeq valid?

	private volatile boolean closed;
	private long lastActive;					// time of the last received packet
	private long handshakeStart;

	private ScheduledFuture<?> retransmitTask;

	/**
	 * Create a new UDPConnection.
	 * @param connectionManager the ConnectionManager
	 * @param socket the shared DatagramSocket
	 * @param peer the remote address
	 * @param networkKeyBytes the network wide key used during the handshake
	 */
	public UDPConnection(ConnectionManager connectionManager, DatagramSocket socket,
			SocketAddress peer, byte[] networkKeyBytes) {
		this.connectionManager = connectionManager;
		this.socket = socket;
		this.peer = (InetSocketAddress) peer;
		this.networkKey = CryptoUtils.decodeSymmetricKey(networkKeyBytes);
		this.netEncOut = CryptoUtils.getSymmetricCipher();
		this.netEncIn = CryptoUtils.getSymmetricCipher();
		bwIn = new MeasureBandwidth(BUCKET_TIME, BUCKET_LEN);
		bwOut = new MeasureBandwidth(BUCKET_TIME, BUCKET_LEN);
		closed = false;
		gotData = false;
		gotSeq = false;
		sendSeq = 0;
		lastActive = System.currentTimeMillis();
		handshakeStart = System.currentTimeMillis();

		// the P2PConnection sends its access invitation in its constructor
		connectionManager.newConnection(this);

		retransmitTask = connectionManager.getScheduledExecutor().scheduleWithFixedDelay(
				new Runnable() {
					public void run() {
						retransmit();
					}
				}, RETRANSMIT_MS, RETRANSMIT_MS, TimeUnit.MILLISECONDS);
	}

	/**
	 * Is the given data the beginning of a tunnel packet?
	 * @param data the buffer
	 * @param off the offset
	 * @param len the length
	 * @return is it a tunnel packet?
	 */
	static boolean isTunnelPacket(byte[] data, int off, int len) {
		return len >= 2 && data[off] == MAGIC;
	}

	/**
	 * Change the encryption key used for data packets. This is called when the
	 * handshake is finished.
	 * @param keyBytes the new key
	 */
	public void changeKey(byte[] keyBytes) {
		SecretKey key = CryptoUtils.decodeSymmetricKey(keyBytes);
		Cipher out = CryptoUtils.getSymmetricCipher();
		Cipher in = CryptoUtils.getSymmetricCipher();
		synchronized (this) {
			peerKey = key;
			peerEncOut = out;
			peerEncIn = in;
		}
	}

	private synchronized boolean isPeerKeyed() {
		return peerKey != null;
	}

	/**
	 * Send a handshake packet containing the access invitation.
	 * @param packet the access invitation
	 */
	public void sendHandshakeAccess(byte[] packet) {
		synchronized (this) {
			handshakeAccess = packet;
		}
		sendHandshakePackets();
	}

	/**
	 * Send a handshake packet containing the encrypted key part.
	 * @param packet the encrypted key part
	 */
	public void sendHandshakeKey(byte[] packet) {
		synchronized (this) {
			handshakeKey = packet;
		}
		sendHandshakePackets();
	}

	/**
	 * Send a VPN data packet. Only packets that arrive after the handshake can
	 * be decrypted, so anything sent before is silently dropped.
	 * @param packet the packet
	 * @param highPriority has this packet a high priority?
	 */
	public void send(byte[] packet, boolean highPriority) {
		if (closed || !isPeerKeyed()) return;
		sendData(packet);
	}

	/**
	 * Handle an incoming datagram.
	 * @param data the buffer
	 * @param off the offset of the packet in the buffer
	 * @param len the length of the packet
	 */
	public void handlePacket(byte[] data, int off, int len) {
		if (closed) return;
		if (!isTunnelPacket(data, off, len)) return;

		lastActive = System.currentTimeMillis();
		bwIn.countPacket(len);

		byte type = data[off + 1];
		switch (type) {
			case TYPE_HANDSHAKE:
				handleHandshake(data, off, len);
				break;
			case TYPE_DATA:
				handleData(data, off, len);
				break;
			default:
				// ignore unknown packet types
		}
	}

	private void handleHandshake(byte[] data, int off, int len) {
		byte[] packet = decrypt(netEncIn, networkKey, data, off + 2, off + 2 + IV_LENGTH,
				len - 2 - IV_LENGTH);
		if (packet == null || packet.length < 1) return;

		byte phase = packet[0];
		byte[] body = new byte[packet.length - 1];
		System.arraycopy(packet, 1, body, 0, body.length);

		if (listener != null) listener.receiveHandshake(phase, body);

		// The peer is still (re)sending its handshake. If we already switched
		// to the peer key but did not receive any data yet, it means the peer
		// did not receive our key part yet, so send our handshake again.
		if (isPeerKeyed() && !gotData) sendHandshakePackets();
	}

	private void handleData(byte[] data, int off, int len) {
		if (len < 2 + 4 + IV_LENGTH) return;
		if (!isPeerKeyed()) return;		// no key yet, cannot decrypt

		int seq = readInt(data, off + 2);
		byte[] packet = decrypt(peerEncIn, peerKey, data, off + 6, off + 6 + IV_LENGTH,
				len - 6 - IV_LENGTH);
		if (packet == null) return;

		if (gotSeq && seq - lastSeq <= 0) return;	// duplicate or reordered (old) packet
		lastSeq = seq;
		gotSeq = true;

		if (!gotData) {
			gotData = true;
			cancelRetransmit();
		}

		if (listener != null) listener.receive(packet);
	}

	/**
	 * Resend the handshake packets while the peer did not yet prove that it
	 * received our key.
	 */
	private void retransmit() {
		if (closed) return;
		if (gotData) {
			cancelRetransmit();
			return;
		}
		if (System.currentTimeMillis() - handshakeStart > HANDSHAKE_MAX_MS) {
			cancelRetransmit();
			return;
		}
		sendHandshakePackets();
	}

	/**
	 * Send all handshake packets we have so far.
	 */
	private void sendHandshakePackets() {
		byte[] access, key;
		synchronized (this) {
			access = handshakeAccess;
			key = handshakeKey;
		}
		if (access != null) sendHandshake(HANDSHAKE_ACCESS, access);
		if (key != null) sendHandshake(HANDSHAKE_KEY, key);
	}

	private void sendHandshake(byte phase, byte[] payload) {
		if (closed) return;

		byte[] plain = new byte[1 + payload.length];
		plain[0] = phase;
		System.arraycopy(payload, 0, plain, 1, payload.length);

		byte[] iv = new byte[IV_LENGTH];
		byte[] ct = encrypt(netEncOut, networkKey, plain, iv);
		if (ct == null) return;

		byte[] packet = new byte[2 + IV_LENGTH + ct.length];
		packet[0] = MAGIC;
		packet[1] = TYPE_HANDSHAKE;
		System.arraycopy(iv, 0, packet, 2, IV_LENGTH);
		System.arraycopy(ct, 0, packet, 2 + IV_LENGTH, ct.length);
		sendRaw(packet);
	}

	private void sendData(byte[] plain) {
		if (plain.length > MAX_PACKET_SIZE) {
			Logger.getLogger("").log(Level.WARNING, "Packet to "+peer+" too large ("+plain.length+")");
			return;
		}

		Cipher cipher;
		SecretKey key;
		synchronized (this) {
			cipher = peerEncOut;
			key = peerKey;
		}
		if (cipher == null || key == null) return;

		byte[] iv = new byte[IV_LENGTH];
		byte[] ct = encrypt(cipher, key, plain, iv);
		if (ct == null) return;

		int seq;
		synchronized (this) {
			seq = sendSeq++;
		}

		byte[] packet = new byte[2 + 4 + IV_LENGTH + ct.length];
		packet[0] = MAGIC;
		packet[1] = TYPE_DATA;
		writeInt(packet, 2, seq);
		System.arraycopy(iv, 0, packet, 6, IV_LENGTH);
		System.arraycopy(ct, 0, packet, 6 + IV_LENGTH, ct.length);
		sendRaw(packet);
	}

	private void sendRaw(byte[] packet) {
		if (closed || socket.isClosed()) return;
		try {
			connectionManager.getSendLimit().waitForTokens(packet.length);
			socket.send(new DatagramPacket(packet, packet.length, peer));
			bwOut.countPacket(packet.length);
		} catch (IOException e) {
			if (!closed && !socket.isClosed()) {
				Logger.getLogger("").log(Level.WARNING, "", e);
			}
		}
	}

	private byte[] encrypt(Cipher cipher, SecretKey key, byte[] plain, byte[] iv) {
		try {
			RANDOM.nextBytes(iv);
			synchronized (cipher) {
				cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
				return cipher.doFinal(plain);
			}
		} catch (Throwable t) {
			Logger.getLogger("").log(Level.SEVERE, null, t);
			return null;
		}
	}

	private byte[] decrypt(Cipher cipher, SecretKey key, byte[] data, int ivOff, int ctOff, int ctLen) {
		if (ctLen <= 0) return null;
		try {
			byte[] iv = new byte[IV_LENGTH];
			System.arraycopy(data, ivOff, iv, 0, IV_LENGTH);
			synchronized (cipher) {
				cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
				return cipher.doFinal(data, ctOff, ctLen);
			}
		} catch (Throwable t) {
			// a packet that cannot be decrypted is dropped (it may be a stale
			// handshake packet or a spoofed datagram)
			return null;
		}
	}

	private static int readInt(byte[] data, int off) {
		return ((0xFF & data[off]) << 24) + ((0xFF & data[off + 1]) << 16)
				+ ((0xFF & data[off + 2]) << 8) + (0xFF & data[off + 3]);
	}

	private static void writeInt(byte[] data, int off, int value) {
		data[off] = (byte) (value >> 24);
		data[off + 1] = (byte) (value >> 16);
		data[off + 2] = (byte) (value >> 8);
		data[off + 3] = (byte) value;
	}

	/**
	 * Set the object of the upper layer.
	 * @param listener the upper layer
	 */
	public void setListener(P2PConnection listener) {
		this.listener = listener;
	}

	/**
	 * Close the connection.
	 */
	public void close() {
		synchronized (this) {
			if (closed) return;
			closed = true;
		}
		cancelRetransmit();
		connectionManager.connectionClosed(this);
		if (listener != null) listener.connectionClosed();
	}

	private synchronized void cancelRetransmit() {
		if (retransmitTask != null) {
			retransmitTask.cancel(false);
			retransmitTask = null;
		}
	}

	@Override
	public String toString() {
		return SocketAddrStr.socketAddrToStr(peer);
	}

	public String getRemoteHost() {
		return peer.getAddress().getHostAddress();
	}

	public InetSocketAddress getPeer() {
		return peer;
	}

	public MeasureBandwidth getBwIn() {
		return bwIn;
	}

	public MeasureBandwidth getBwOut() {
		return bwOut;
	}

	public long getLastActive() {
		return lastActive;
	}
}
