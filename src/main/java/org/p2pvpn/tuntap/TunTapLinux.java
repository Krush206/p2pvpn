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

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The TunTap class for linux.
 * @author Wolfgang  Ginolas
 */
public class TunTapLinux extends TunTap {

	private static boolean libLoaded = false;

    static {
		try {
			String arch = System.getProperty("os.arch", "");

			if ("amd64".equals(arch) || "x86_64".equals(arch)) {
				// 64 bit x86
				loadLib("clib/libTunTapLinux64.so", "clib/libTunTapLinux.so");
			} else if (arch.startsWith("mips")) {
				loadLib("clib/libTunTapLinuxMips.so");
			} else {
				// 32 bit x86 and everything else: try all libraries
				loadLib("clib/libTunTapLinux.so", "clib/libTunTapLinux64.so", "clib/libTunTapLinuxMips.so");
			}
			libLoaded = true;
		} catch (Throwable e) {
			Logger.getLogger("").log(Level.SEVERE, "Could not load the tun/tap library", e);
		}
    }

    private int fd;
    private String dev;    

	/**
	 * Create a new TunTapLinux
	 * @throws java.lang.Exception
	 */
    public TunTapLinux() throws Exception {
    	if (!libLoaded) {
			throw new Exception("The tun/tap library could not be loaded (see the log above).");
		}
        if (1==openTun()) throw new Exception("Could not open '/dev/net/tun!'\n" +
				"Please run this application as root.");
    }
    
    public String getDev() {
        return dev;
    }
    
    private native int openTun();
    
    public native void close();
    
    public native void write(byte[] b, int len);
    
    public native int read(byte[] b);
    
    public void setIP(String ip, String subnetmask) {
		super.setIP(ip, subnetmask);
    	try {
    		Process p = Runtime.getRuntime().exec("ifconfig "+dev+" "+ip+" netmask "+subnetmask);
			Logger.getLogger("").log(Level.INFO, "IP set successfully ("+p.waitFor()+")");
    	} catch (Exception e) {
			Logger.getLogger("").log(Level.WARNING, "Could not set IP!", e);
    	}
    }
    
}
