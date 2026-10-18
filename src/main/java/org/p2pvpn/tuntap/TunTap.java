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

package org.p2pvpn.tuntap;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * An apstract claas for an virtual network adapter. A different implementation
 * for every operating system is needed.
 * @author Wolfgang Ginolas
 */
public abstract class TunTap {

	private byte[] ip = null;

	/**
	 * Load a libary (*.so or *.dll).
	 *
	 * Every library is searched in this order:
	 * 1. as a file relative to the current directory (e.g. when running
	 *    directly from the source tree, where the clib directory is)
	 * 2. as a resource in the classpath (e.g. when running the '-bin' jar,
	 *    which contains the clib directory). The resource has to be extracted
	 *    into a temporary file first, because Java cannot load a library
	 *    directly out of a jar.
	 *
	 * If no library could be loaded, an exception listing every attempt is
	 * thrown. (Only the last attempt used to be reported, which was very
	 * misleading, e.g. a mips library on a x86-64 system.)
	 * @param libs the libary names
	 */
	static void loadLib(String... libs) throws IOException {
		StringBuffer tried = new StringBuffer();
		Throwable first = null;

		for (String lib : libs) {
			File file = new File(lib);
			String resource = lib.replace('\\', '/');
			try {
				if (file.exists()) {
					System.load(file.getCanonicalPath());
					return;
				}
				if (loadLibFromClasspath(resource)) {
					return;
				}
				tried.append("  ").append(lib).append(": no file '").append(file.getCanonicalPath())
						.append("' and no such resource in the classpath\n");
			} catch (Throwable t) {
				if (first==null) first = t;
				tried.append("  ").append(lib).append(": ").append(t.getMessage()).append('\n');
			}
		}

		IOException result = new IOException("Could not load a native library for "
				+ System.getProperty("os.name") + " " + System.getProperty("os.arch") + ". Tried:\n"
				+ tried + "Run the program from a directory containing 'clib' or use the '-bin' jar.");
		if (first!=null) result.initCause(first);
		throw result;
	}

	/**
	 * Load a libary from the classpath. Because Java cannot load a library
	 * directly out of a jar or the classpath, it is copied into a temporary
	 * file first.
	 * @param resource the name of the resource (e.g. "clib/libTunTapLinux64.so")
	 * @return was the resource found and loaded?
	 */
	static private boolean loadLibFromClasspath(String resource) throws IOException {
		InputStream in = TunTap.class.getClassLoader().getResourceAsStream(resource);
		if (in == null) return false;

		String suffix = resource.substring(resource.lastIndexOf('.'));
		File tmp = File.createTempFile("p2pvpn-", suffix);
		tmp.deleteOnExit();

		OutputStream out = new FileOutputStream(tmp);
		try {
			byte[] buffer = new byte[8 * 1024];
			int len;
			while (0 < (len = in.read(buffer))) out.write(buffer, 0, len);
		} finally {
			in.close();
			out.close();
		}

		System.load(tmp.getCanonicalPath());
		return true;
	}

	/**
	 * Return a TunTap object for the currently used operating system.
	 * @return the TunTap object
	 * @throws java.lang.Exception
	 */
    static public TunTap createTunTap() throws Exception {
        String osName = System.getProperty("os.name");
        
        if (osName.startsWith("Windows")) {
            return new TunTapWindows();
        } else if (osName.equals("Linux")) {
            return new TunTapLinux();
        } else {
            throw new Exception("The operating system "+osName+" is not supported!");
        }
    }

	/**
	 * @return the name of the virtuel network device
	 */
    abstract public String getDev();

	/**
	 * Close the device.
	 */
    abstract public void close();

	/**
	 * Send a packet to the virtual network adapter.
	 * @param b the packet
	 * @param len the length of the packet
	 */
    abstract public void write(byte[] b, int len);

	/**
	 * Read a packet from the virtual network adapter.
	 * @param b the packet
	 * @return length if the packet
	 */
    abstract public int read(byte[] b);

	/**
	 * Set the IP address of the virtual network adapter.
	 * @param ip the IP
	 * @param subnetmask the subnet mask
	 */
    public void setIP(String ip, String subnetmask) {
		try {
			this.ip = InetAddress.getByName(ip).getAddress();
		} catch (UnknownHostException ex) {
		}
	}

	/**
	 * Return the last set IP address.
	 * @return the ip address
	 */
	public byte[] getIPBytes() {
		return ip;
	}

}
