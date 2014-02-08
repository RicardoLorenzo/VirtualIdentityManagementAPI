/*
 * LDAPConnection class
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
package com.ricardolorenzo.directory.ldap;

/**
 * LDAP connection representation
 * 
 * @author: Ricardo Lorenzo
 * @version 0.1
 */
import java.io.File;
import java.util.Hashtable;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import com.ricardolorenzo.directory.DirectoryException;

public class LDAPConnection {
    private final static Logger log = Logger.getLogger(LDAPConnection.class.getName());
    public static final int DEFAULT_PORT = 389;
    public static final int AUTHENTICATION_NONE = 1;
    public static final int AUTHENTICATION_SIMPLE = 2;
    public static final int AUTHENTICATION_STRONG = 3;
    public static final int RO = 0;
    public static final int RW = 1;
    public static final int SUBTREE_SCOPE = SearchControls.SUBTREE_SCOPE;
    public static final int ONE_SCOPE = SearchControls.ONELEVEL_SCOPE;
    public static final int OBJECT_SCOPE = SearchControls.OBJECT_SCOPE;
    private Hashtable<String, String> env;
    private LdapContext ctx;
    private String server;
    private int port;
    private boolean secure = false;
    private int countLimit = -1;
    private int scope = SearchControls.SUBTREE_SCOPE;

    /**
     * LDAPConnection constructor
     * 
     * @param server
     *            Server name or address
     * @exception LDAPException
     */
    public LDAPConnection(final String server) throws LDAPException {
        env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.REFERRAL, "follow");
        this.server = server;
        port = DEFAULT_PORT;
    }

    /**
     * LDAPConnection. constructor
     * 
     * @param server
     *            Server name or address
     * @param port
     *            Server port
     * @exception LDAPException
     */
    public LDAPConnection(final String server, final int port) {
        env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.REFERRAL, "follow");
        this.server = server;
        this.port = port;
    }

    /**
     * Authenticate an user using a DistinguishedName and password
     * 
     * @param DN
     *            String representing a Distinguished Name
     * @param password
     *            String
     * @exception LDAPException
     */
    public void authenticate(final String DN, final String password) throws LDAPException {
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, DN);
        env.put(Context.SECURITY_CREDENTIALS, password);
        connect();
        disconnect();
    }

    /**
     * Authenticate an user using a DistinguishedName and password, and indicating the type of
     * authentication:
     * 
     * <code>LDAPConnection.NONE_AUTHENTICATION</code>
     * <code>LDAPConnection.SIMPLE_AUTHENTICATION</code>
     * <code>LDAPConnection.STRONG_AUTHENTICATION</code>
     * 
     * @param DN
     *            String representing a Distinguished Name
     * @param password
     *            String
     * @param authenticationType
     *            String
     * @exception LDAPException
     */
    public void authenticate(final String DN, final String password, final int authenticationType) throws LDAPException {
        if (password == null || password.isEmpty()) {
            throw new LDAPException("Invalid empty password");
        }
        switch (authenticationType) {
            default:
                throw new LDAPException("Invalid authentication type");
            case AUTHENTICATION_NONE:
                env.put(Context.SECURITY_AUTHENTICATION, "none");
                break;
            case AUTHENTICATION_SIMPLE:
                env.put(Context.SECURITY_AUTHENTICATION, "simple");
                break;
            case AUTHENTICATION_STRONG:
                env.put(Context.SECURITY_AUTHENTICATION, "strong");
                break;
        }
        env.put(Context.SECURITY_PRINCIPAL, DN);
        env.put(Context.SECURITY_CREDENTIALS, password);
        connect();
        disconnect();
    }

    /**
     * Start a connection to the server
     * 
     * @return DirContext
     * @exception LDAPException
     */
    protected LdapContext connect() throws LDAPException {
        return connect(RO);
    }

    /**
     * Start a connection to the server and specify if the connection is read only or read-write
     * 
     * <code>LDAPConnection.RO</code> <code>LDAPConnection.RW</code>
     * 
     * @param type
     *            int
     * @return DirContext
     * @exception LDAPException
     */
    protected LdapContext connect(final int type) throws LDAPException {
        try {
            if (ctx == null) {
                env.put("java.naming.ldap.attributes.binary",
                        "jpegPhoto userCertificate userSMIMECertificate userPKCS12 cACertificate");
                if (type == RW) {
                    if (secure) {
                        if (port == DEFAULT_PORT) {
                            env.put(Context.PROVIDER_URL, "ldaps://" + server + ":636");
                        } else {
                            env.put(Context.PROVIDER_URL, "ldaps://" + server + ":" + port);
                        }
                    } else {
                        env.put(Context.PROVIDER_URL, "ldap://" + server + ":" + port);
                    }
                } else {
                    if (secure) {
                        if (port == DEFAULT_PORT) {
                            env.put(Context.PROVIDER_URL, "ldaps://" + server + ":636");
                        } else {
                            env.put(Context.PROVIDER_URL, "ldaps://" + server + ":" + port);
                        }
                    } else {
                        env.put(Context.PROVIDER_URL, "ldap://" + server + ":" + port);
                    }
                }
                ctx = new InitialLdapContext(env, null);
                if (ctx == null) {
                    throw new LDAPException("Unknown directory error - " + env.get(Context.PROVIDER_URL));
                }
            }
            return ctx;
        } catch (NullPointerException e) {
            log.log(java.util.logging.Level.ALL, "connect() null pointer");
            throw new LDAPException("Unknown directory error - " + env.get(Context.PROVIDER_URL));
        } catch (NamingException e) {
            log.log(java.util.logging.Level.ALL, "connect() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        }
    }

    /**
     * Close the connection with the server
     * 
     * @exception LDAPException
     */
    public void disconnect() throws LDAPException {
        try {
            if (ctx != null) {
                ctx.close();
                ctx = null;
            }
        } catch (NullPointerException e) {
            log.log(java.util.logging.Level.ALL, "disconnect() null pointer");
            throw new LDAPException("Unknown directory error - " + env.get(Context.PROVIDER_URL));
        } catch (NamingException e) {
            log.log(java.util.logging.Level.ALL, "disconnect() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        }
    }

    /**
     * Return the connection count limit
     * 
     * @return int
     */
    public int getCountLimit() {
        return countLimit;
    }

    /**
     * Returns the scope of the connection
     * 
     * @return int
     */
    public int getScope() {
        return scope;
    }

    /**
     * Verify if the connection has a count limit
     * 
     * @return boolean
     */
    public boolean hasCountLimit() {
        if (countLimit > 0) {
            return true;
        }
        return false;
    }

    /**
     * Verify if the connection use Secure Socket Layers
     * 
     * @return boolean
     */
    public boolean isSecure() {
        return secure;
    }

    /**
     * Set the count limit of the connections
     * 
     * @param limit
     *            int
     */
    public void setCountLimit(final int limit) {
        if (limit > 0 || limit == -1) {
            countLimit = limit;
        }
    }

    /**
     * Define if the connection must be persistent
     * 
     * @param limit
     *            int
     */
    public void setConnectionPool(final boolean status) {
        if (status) {
            env.put("com.sun.jndi.ldap.connect.pool", "true");
            env.put("com.sun.jndi.ldap.connect.pool.timeout", "3600000");
        } else if (env.containsKey("com.sun.jndi.ldap.connect.pool")) {
            env.remove("com.sun.jndi.ldap.connect.pool");
            env.remove("com.sun.jndi.ldap.connect.pool.timeout");
        }
    }

    /**
     * Set connection port
     * 
     * @param int LDAP connection port
     */
    public void setPort(final int port) {
        this.port = port;
    }

    /**
     * Enable Secure Socket layers on the connection
     * 
     * @param value
     *            A boolean value
     * @exception LDAPException
     */
    public void setSecure(final boolean value) throws LDAPException {
        if (value) {
            env.put("java.naming.ldap.factory.socket", "com.ricardolorenzo.directory.ldap.ssl.LDAPSSocketFactory");
            env.put(Context.SECURITY_PROTOCOL, "ssl");
            secure = true;
        } else {
            env.remove("java.naming.ldap.factory.socket");
            env.remove(Context.SECURITY_PROTOCOL);
            secure = false;
        }
    }

    /**
     * Enable Secure Socket layers on the connection
     * 
     * @param certificateStore
     *            A file for a certificate store
     * @exception LDAPException
     */
    public void setSecure(final File certificateStore) throws LDAPException {
        if (certificateStore != null && certificateStore.exists()) {
            System.setProperty("javax.net.ssl.trustStore", certificateStore.getAbsolutePath());
            env.put(Context.SECURITY_PROTOCOL, "ssl");
            secure = true;
        } else {
            System.clearProperty("javax.net.ssl.trustStore");
            env.remove("java.naming.ldap.factory.socket");
            env.remove(Context.SECURITY_PROTOCOL);
            secure = false;
        }
    }

    /**
     * Define the scope of the connection:
     * 
     * <code>LDAPConnection.OBJECT_SCOPE</code> <code>LDAPConnection.ONELEVEL_SCOPE</code>
     * <code>LDAPConnection.SUBTREE_SCOPE</code>
     * 
     * @param scope
     *            int
     */
    public void setScope(final int scope) throws DirectoryException {
        switch (scope) {
            case OBJECT_SCOPE:
                break;
            case ONE_SCOPE:
                break;
            case SUBTREE_SCOPE:
                break;
            default:
                throw new DirectoryException("invalid scope");
        }
        this.scope = scope;
    }

    /**
     * Sets the timeout of the connection
     * 
     * @param milliseconds
     *            int
     */
    public void setTimeout(final int milliseconds) {
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(Math.abs(milliseconds)));
    }

    /**
     * Sets an user entry to bind connection
     * 
     * @param DN
     *            String
     * @param password
     *            String
     * @exception LDAPException
     */
    public void setUser(final String DN, final String password) throws LDAPException {
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, DN);
        env.put(Context.SECURITY_CREDENTIALS, password);
    }
}
