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

import java.io.ByteArrayOutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.p2pvpn.tools.SocketAddrStr;

/**
 * This class establishes direct connections between peers that are currently
 * only connected indirectly through the mesh, using UDP hole punching.
 *
 * Two things are needed for a hole punch:
 *
 * 1. Every peer has to know its public address (IP and port) as seen from
 *    outside its NAT. A peer cannot find this out on its own, but its direct
 *    connections know it: the source address of their packets is the NAT
 *    mapping of the peer. So every direct connection tells its peer which
 *    address it observes ("I see you at 203.0.113.7:53122"). The peer
 *    publishes this address as "local.extAddr4"/"local.extAddr6" in its peer
 *    database, which the mesh synchronises anyway. There is one entry per
 *    address family, because on a dual stack the observed IPv4 and IPv6
 *    addresses of a peer differ.
 *
 * 2. Both peers have to send packets to each other at the same time, because
 *    most NATs only let a packet pass if the peer sent a packet to that
 *    address before. Therefore a peer sends a punch request through the mesh
 *    (which works, because the peers are connected indirectly) and both
 *    peers start sending to each others addresses at the same time.
 *
 * The punch request contains the addresses of the sender, so the receiver
 * does not need to know them yet. If both NATs use one mapping per internal
 * port (cone NAT), the punch will succeed. With a symmetric NAT the mapping
 * contains a different port for every destination, so the learned address is
 * wrong and the peers stay connected indirectly through the mesh.
 *
 * @author Wolfgang Ginolas
 */
public class HolePuncher implements InternalPacketListener {

	private final static long FIRST_PUNCH_MS = 5 * 1000;
	private final static long PUNCH_INTERVALL_MS = 20 * 1000;
	/** maximum number of addresses in one packet */
	private final static int MAX_ENDPOINTS = 8;
	/** maximum number of peers punched per round */
	private final static int MAX_PUNCHES = 5;

	/** peer info keys for the observed public addresses */
	private final static String EXT_ADDR4 = "local.extAddr4";
	private final static String EXT_ADDR6 = "local.extAddr6";

	private final static byte MSG_OBSERVED = 0;			// "this is your address as I see it"
	private final static byte MSG_PUNCH_REQUEST = 1;	// "let's punch, here are my addresses"
	private final static byte MSG_PUNCH_REPLY = 2;		// "here are my addresses"

	/** how long a published external address is kept, even if another peer
	 * observes a different address */
	private final static long STALE_MS = 60 * 1000;

	private ConnectionManager connectionManager;	// the ConnectionManager
	private Router router;							// the Router

	private long confirmed4;		// when was local.extAddr4 last observed
	private long confirmed6;		// when was local.extAddr6 last observed

	/**
	 * Create a new HolePuncher.
	 * @param connectionManager the ConnectionManager
	 */
	public HolePuncher(ConnectionManager connectionManager) {
		this.connectionManager = connectionManager;
		this.router = connectionManager.getRouter();

		router.addInternalPacketListener(Router.INTERNAL_PORT_PUNCH, this);

		connectionManager.getScheduledExecutor().schedule(new Runnable() {
			public void run() {
				punchRound();
			}
		}, FIRST_PUNCH_MS, TimeUnit.MILLISECONDS);
	}

	/**
	 * Schedule the next round.
	 */
	private void scheduleRound() {
		connectionManager.getScheduledExecutor().schedule(new Runnable() {
			public void run() {
				punchRound();
			}
		}, PUNCH_INTERVALL_MS, TimeUnit.MILLISECONDS);
	}

	/**
	 * One punch round: tell the direct connections which address we observe
	 * and start synchronized punches with indirectly connected peers.
	 */
	private void punchRound() {
		try {
			sendObservedAddresses();
			sendPunchRequests();
		} catch (Throwable t) {
			Logger.getLogger("").log(Level.WARNING, "", t);
		}
		scheduleRound();
	}

	/**
	 * Called, when a new direct connection was established. Tell the peer
	 * which address we observe, so it can publish it.
	 * @param connection the new connection
	 */
	public void directConnection(P2PConnection connection) {
		try {
			String macStr = router.getPeerInfo(connection.getRemoteAddr(), "vpn.mac");
			if (macStr==null) return;

			InetSocketAddress observed = connection.getConnection().getPeer();
			if (observed==null || observed.getAddress()==null) return;

			List<InetSocketAddress> endpoints = new LinkedList<InetSocketAddress>();
			endpoints.add(observed);
			router.sendInternalPacket(new MacAddress(macStr), Router.INTERNAL_PORT_PUNCH,
					encodePacket(MSG_OBSERVED, endpoints));
		} catch (Throwable t) {
			Logger.getLogger("").log(Level.WARNING, "", t);
		}
	}

	/**
	 * Tell every direct connection which address we observe.
	 */
	private void sendObservedAddresses() {
		P2PConnection[] cs = router.getConnections();
		for (P2PConnection c : cs) {
			directConnection(c);
		}
	}

	/**
	 * Ask all indirectly connected peers to punch.
	 */
	private void sendPunchRequests() {
		List<InetSocketAddress> mine = myEndpoints();
		PeerID me = connectionManager.getLocalAddr();

		PeerID[] peers = router.getPeers();
		int punches = 0;
		for (PeerID p : peers) {
			if (punches >= MAX_PUNCHES) break;
			if (p.equals(me) || router.isConnectedTo(p)) continue;

			String macStr = router.getPeerInfo(p, "vpn.mac");
			if (macStr==null) continue;

			// punch toward the peer's known addresses ...
			dial(peerEndpoints(p), mine);
			// ... and ask the peer to punch back at the same time
			router.sendInternalPacket(new MacAddress(macStr), Router.INTERNAL_PORT_PUNCH,
					encodePacket(MSG_PUNCH_REQUEST, mine));
			punches++;
		}
	}

	/**
	 * Called, when a peer told us which address it observes. The address is
	 * published in our peer database, so all peers of the mesh learn how to
	 * reach us from outside.
	 *
	 * Different peers can observe different addresses (for example one peer
	 * in the local network sees our LAN address while a peer behind another
	 * NAT sees our public mapping). A public address is more useful for the
	 * other peers of the mesh, so it replaces a private address. Otherwise
	 * the first observed address is kept as long as it gets confirmed, so
	 * the published address does not flap.
	 * @param endpoints the address of this peer as seen by the sender
	 */
	private void handleObserved(List<InetSocketAddress> endpoints) {
		if (endpoints.isEmpty()) return;
		InetSocketAddress observed = endpoints.get(0);
		if (observed.getAddress()==null) return;

		boolean ipv6 = observed.getAddress() instanceof Inet6Address;
		String key = ipv6 ? EXT_ADDR6 : EXT_ADDR4;
		String addr = SocketAddrStr.socketAddrToStr(observed);
		String current = router.getPeerInfo(connectionManager.getLocalAddr(), key);
		long now = System.currentTimeMillis();

		if (addr.equals(current)) {
			if (ipv6) confirmed6 = now; else confirmed4 = now;
			return;
		}

		boolean replace = current==null
				|| now - (ipv6 ? confirmed6 : confirmed4) > STALE_MS
				|| (isPrivate(current) && !isPrivate(addr));

		if (replace) {
			Logger.getLogger("").log(Level.INFO, "my external address seems to be "+addr);
			if (ipv6) confirmed6 = now; else confirmed4 = now;
			router.setLocalPeerInfo(key, addr);
		}
	}

	/**
	 * Is the given address a private address (loopback, link local or site
	 * local)? A public address is more valuable for the other peers, because
	 * most of them are not in our local network.
	 * @param addr the address in the format "host:port"
	 * @return is it private?
	 */
	private boolean isPrivate(String addr) {
		try {
			InetAddress a = SocketAddrStr.parseSocketAddr(addr).getAddress();
			if (a==null) return true;
			if (a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress()) return true;
			if (a instanceof Inet6Address && (a.getAddress()[0] & 0xFE) == 0xFC) return true;
			return false;
		} catch (IllegalArgumentException e) {
			return true;
		}
	}

	/**
	 * Called, when a peer asked us to punch. Send packets to the addresses of
	 * the peer and tell it our addresses, so it can do the same.
	 * @param from the MAC of the peer
	 * @param endpoints the addresses of the peer
	 */
	private void handlePunchRequest(MacAddress from, List<InetSocketAddress> endpoints) {
		List<InetSocketAddress> mine = myEndpoints();
		dial(endpoints, mine);
		router.sendInternalPacket(from, Router.INTERNAL_PORT_PUNCH,
				encodePacket(MSG_PUNCH_REPLY, mine));
	}

	/**
	 * Called, when a peer answered our punch request. Send packets to the
	 * addresses of the peer.
	 * @param endpoints the addresses of the peer
	 */
	private void handlePunchReply(List<InetSocketAddress> endpoints) {
		dial(endpoints, myEndpoints());
	}

	/**
	 * Try to connect to the given addresses. Our own addresses are skipped,
	 * so we do not try to connect to ourself.
	 * @param endpoints the addresses to connect to
	 * @param exclude addresses of our own
	 */
	private void dial(List<InetSocketAddress> endpoints, List<InetSocketAddress> exclude) {
		for (InetSocketAddress ep : endpoints) {
			if (ep.getAddress()==null || exclude.contains(ep)) continue;
			connectionManager.connectTo(ep.getAddress(), ep.getPort());
		}
	}

	/**
	 * Return the addresses other peers can use to reach us: the observed
	 * public address first (this is the interesting one for hole punching),
	 * then the addresses of the local network adapters.
	 * @return the addresses
	 */
	private List<InetSocketAddress> myEndpoints() {
		List<InetSocketAddress> result = new LinkedList<InetSocketAddress>();
		PeerID me = connectionManager.getLocalAddr();

		addParsed(result, router.getPeerInfo(me, EXT_ADDR4));
		addParsed(result, router.getPeerInfo(me, EXT_ADDR6));

		int port = connectionManager.getServerPort();
		addAll(result, router.getPeerInfo(me, "local.ips"), port);
		addAll(result, router.getPeerInfo(me, "local.ip6s"), port);

		return result;
	}

	/**
	 * Return the known addresses of a peer.
	 * @param p the peer
	 * @return the addresses
	 */
	private List<InetSocketAddress> peerEndpoints(PeerID p) {
		List<InetSocketAddress> result = new LinkedList<InetSocketAddress>();

		addParsed(result, router.getPeerInfo(p, EXT_ADDR4));
		addParsed(result, router.getPeerInfo(p, EXT_ADDR6));

		int port = -1;
		try {
			port = Integer.parseInt(router.getPeerInfo(p, "local.port"));
		} catch (NumberFormatException e) {
		}
		if (port > 0) {
			addAll(result, router.getPeerInfo(p, "local.ips"), port);
			addAll(result, router.getPeerInfo(p, "local.ip6s"), port);
		}
		return result;
	}

	private void addParsed(List<InetSocketAddress> result, String addr) {
		try {
			InetSocketAddress ep = SocketAddrStr.parseSocketAddr(addr);
			if (ep.getAddress()!=null && !result.contains(ep) && result.size()<MAX_ENDPOINTS) {
				result.add(ep);
			}
		} catch (IllegalArgumentException e) {
			// not a valid address, ignore it
		}
	}

	private void addAll(List<InetSocketAddress> result, String addrs, int port) {
		if (addrs==null || port<=0) return;
		StringTokenizer st = new StringTokenizer(addrs);
		while (st.hasMoreTokens() && result.size()<MAX_ENDPOINTS) {
			try {
				InetSocketAddress ep = new InetSocketAddress(
						InetAddress.getByName(st.nextToken()), port);
				if (!result.contains(ep)) result.add(ep);
			} catch (UnknownHostException e) {
				// ignore this address
			}
		}
	}

	/**
	 * Encode a punch packet.
	 * @param msg the type of the message
	 * @param endpoints our addresses
	 * @return the packet
	 */
	private byte[] encodePacket(byte msg, List<InetSocketAddress> endpoints) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		byte[] mac = router.getMyMAC().getAddress();
		out.write(mac, 0, 6);		// sender
		out.write(msg);

		for (InetSocketAddress ep : endpoints) {
			byte[] addr = ep.getAddress().getAddress();
			if (addr.length!=4 && addr.length!=16) continue;
			out.write(addr.length);
			out.write(addr, 0, addr.length);
			out.write((ep.getPort() >> 8) & 0xFF);
			out.write(ep.getPort() & 0xFF);
		}
		return out.toByteArray();
	}

	/**
	 * Decode the addresses contained in a punch packet.
	 * @param packet the packet
	 * @param off the offset of the address list
	 * @return the addresses
	 */
	private List<InetSocketAddress> decodeEndpoints(byte[] packet, int off) {
		List<InetSocketAddress> result = new LinkedList<InetSocketAddress>();
		try {
			while (off < packet.length) {
				int addrLen = 0xFF & packet[off];
				off++;
				if (addrLen!=4 && addrLen!=16) break;
				if (off + addrLen + 2 > packet.length) break;

				byte[] addr = new byte[addrLen];
				System.arraycopy(packet, off, addr, 0, addrLen);
				off += addrLen;
				int port = ((0xFF & packet[off]) << 8) + (0xFF & packet[off + 1]);
				off += 2;

				InetSocketAddress ep = new InetSocketAddress(InetAddress.getByAddress(addr), port);
				if (!result.contains(ep) && result.size()<MAX_ENDPOINTS) result.add(ep);
			}
		} catch (UnknownHostException e) {
			// cannot happen, the length was checked
		}
		return result;
	}

	/**
	 * Called, when a punch packet arrived.
	 * @param router the Router
	 * @param internalPort the internal port
	 * @param packet the packet
	 */
	public void receiveInternalPacket(Router router, byte internalPort, byte[] packet) {
		if (internalPort != Router.INTERNAL_PORT_PUNCH) return;
		if (packet.length < 7) return;

		MacAddress from = new MacAddress(packet, 0);
		byte msg = packet[6];
		List<InetSocketAddress> endpoints = decodeEndpoints(packet, 7);

		switch (msg) {
			case MSG_OBSERVED:
				handleObserved(endpoints);
				break;
			case MSG_PUNCH_REQUEST:
				handlePunchRequest(from, endpoints);
				break;
			case MSG_PUNCH_REPLY:
				handlePunchReply(endpoints);
				break;
			default:
				// unknown message type, ignore it
		}
	}
}
