/*
 * LDAPSSocketFactory class
 * 
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program. If
 * not, see <http://www.gnu.org/licenses/>.
 * 
 * Author: Ricardo Lorenzo <unshakablespirit@gmail.com>
 */
package com.ricardolorenzo.directory.ldap.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * 
 * @author Ricardo Lorenzo
 * 
 */
public class LDAPSSocketFactory extends SocketFactory {
    private final static Logger _log = Logger.getLogger(LDAPSSocketFactory.class.getName());
    private static SocketFactory _sf = null;

    static {
        try {
            KeyStore _store = KeyStore.getInstance("JKS");
            TrustManagerFactory _tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            _tmf.init(_store);
            X509TrustManager x509Manager = (X509TrustManager) _tmf.getTrustManagers()[0];
            SSLContext _sslc = SSLContext.getInstance("SSL");
            _sslc.init(null, new TrustManager[] { new LDAPSTrustManager(x509Manager) }, null);
            _sf = _sslc.getSocketFactory();
        } catch (KeyManagementException e) {
            _log.log(java.util.logging.Level.ALL, e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            _log.log(java.util.logging.Level.ALL, e.getMessage());
        } catch (KeyStoreException e) {
            _log.log(java.util.logging.Level.ALL, e.getMessage());
        }
    }

    public static SocketFactory getDefault() {
        return new LDAPSSocketFactory();
    }

    public Socket createSocket(String arg0, int arg1) throws IOException, UnknownHostException {
        return _sf.createSocket(arg0, arg1);
    }

    public Socket createSocket(InetAddress arg0, int arg1) throws IOException {
        return _sf.createSocket(arg0, arg1);
    }

    public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3) throws IOException,
            UnknownHostException {
        return _sf.createSocket(arg0, arg1, arg2, arg3);
    }

    public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2, int arg3) throws IOException {
        return _sf.createSocket(arg0, arg1, arg2, arg3);
    }
}
