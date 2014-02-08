/*
 * DirectoryAuthenticator class
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
package com.ricardolorenzo.directory;

/**
 * Perform authentication against a directory
 * 
 * @author Ricardo Lorenzo
 * @version 0.1
 */
import java.io.File;
import java.util.List;
import java.util.Properties;

import com.ricardolorenzo.directory.ldap.LDAPConnection;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryQuery;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryReader;
import com.ricardolorenzo.directory.ldap.LDAPException;
import com.ricardolorenzo.identity.Identity;

public class DirectoryAuthenticator {
    private Properties conf;
    private LDAPConnection lc;

    /**
     * Creates an instance of the object using <code>Configuration</code> with all the parameters
     * needed, like ldap.host, ldap.manager, ldap.password ldap.basedn, etc.
     * 
     * @param configuration
     *            Configuration
     * @exception DirectoryException
     */
    public DirectoryAuthenticator(final Properties configuration) throws DirectoryException {
        this.conf = configuration;
        try {
            if (this.conf.getProperty("ldap.host") == null || this.conf.getProperty("ldap.basedn") == null) {
                throw new DirectoryException("can't find LDAP properties");
            }
            int port = LDAPConnection.DEFAULT_PORT;
            try {
                port = Integer.parseInt(this.conf.getProperty("ldap.port"));
            } catch (NumberFormatException e) {
                // nothing
            }
            this.lc = new LDAPConnection(this.conf.getProperty("ldap.host"), port);
            if (this.conf.getProperty("ldap.ssl") != null
                    && this.conf.getProperty("ldap.ssl").toLowerCase().equals("true")) {
                this.lc.setSecure(new File(this.conf.getProperty("ldap.ssl.store")));
            }
        } catch (LDAPException e) {
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Performs a user authentication, and returns the proper Distinguished Name
     * 
     * @param user
     *            User name
     * @param password
     *            User password
     * @return String
     * @exception DirectoryException
     */
    public String authenticate(String user, String password) throws DirectoryException {
        try {
            if (this.conf.getProperty("ldap.manager") != null && this.conf.getProperty("ldap.password") != null) {
                this.lc.setUser(this.conf.getProperty("ldap.manager"), this.conf.getProperty("ldap.password"));
            }
            LDAPDirectoryReader qry = new LDAPDirectoryReader(this.lc, this.conf.getProperty("ldap.basedn"));
            LDAPDirectoryQuery _q = new LDAPDirectoryQuery();
            if (this.conf.getProperty("ldap.auth.userID") == null) {
                throw new DirectoryException("can't find ldap.auth.userID");
            }
            _q.addCondition(this.conf.getProperty("ldap.auth.userID"), user, LDAPDirectoryQuery.EXACT);
            List<Identity> _results = qry.search(_q);
            if (_results == null || _results.size() <= 0) {
                throw new DirectoryException("user not found");
            }
            Identity _e = (Identity) _results.get(0);
            if (_e == null) {
                throw new DirectoryException("user not found");
            }
            this.lc.authenticate(_e.getID(), password, LDAPConnection.AUTHENTICATION_SIMPLE);
            return _e.getID();
        } catch (LDAPException e) {
            throw new DirectoryException(e.getMessage());
        }
    }
}
