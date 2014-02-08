/*
 * DirectoryIdentityManager class
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

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.ricardolorenzo.directory.ldap.LDAPConnection;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryEntry;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryQuery;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryReader;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryWriter;
import com.ricardolorenzo.directory.ldap.LDAPException;
import com.ricardolorenzo.identity.Identity;

/**
 * 
 * @author Ricardo Lorenzo
 * @version 0.1
 */
public class DirectoryIdentityManager {
    private Properties properties;
    private LDAPConnection ldapConnection;
    private String baseDN;

    /**
     * Instance a new <code>DirectoryIdentityManager</code> using a Configuration object that must
     * contain some properties like directory.ldap.host, directory.ldap.manager,
     * directory.ldap.password, directory.ldap.basedn, etc.
     * 
     * @param configuration
     *            Configuration object with connection parameters
     * @exception DirectoryException
     */
    public DirectoryIdentityManager(final Properties configuration) throws DirectoryException {
        properties = configuration;
        try {
            if (properties.getProperty("directory.ldap.host") == null
                    || properties.getProperty("directory.ldap.basedn") == null) {
                throw new DirectoryException("invalid ldap properties");
            }
            int port = LDAPConnection.DEFAULT_PORT;
            try {
                port = Integer.parseInt(properties.getProperty("directory.ldap.port"));
            } catch (NumberFormatException e) {
            }
            ldapConnection = new LDAPConnection(properties.getProperty("directory.ldap.host"), port);
            baseDN = properties.getProperty("directory.ldap.basedn");
            if (properties.getProperty("directory.ldap.ssl") != null
                    && properties.getProperty("directory.ldap.ssl").toLowerCase().equals("true")) {
                setSecure(true);
            }
            if (properties.getProperty("directory.ldap.user") != null
                    && properties.getProperty("directory.ldap.password") != null) {
                setUser(properties.getProperty("directory.ldap.user"),
                        properties.getProperty("directory.ldap.password"));
            }
        } catch (LDAPException e) {
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Adds a new entry to the directory
     * 
     * @param e
     *            DirectoryEntry
     * @exception DirectoryException
     */
    public void addIdentity(final Identity e) throws DirectoryException {
        addIdentity(e, LDAPDirectoryWriter.DIRECTORY_TYPE_LDAPV3);
    }

    /**
     * Adds a new entry to the directory
     * 
     * @param e
     *            DirectoryEntry
     * @param int Directory type. This can be <code>LDAPDirectoryEditor.DIRECTORY_TYPE_LDAPV3</code>
     *        or <code>LDAPDirectoryEditor.DIRECTORY_TYPE_MSAD</code>
     * @exception DirectoryException
     */
    public void addIdentity(final Identity i, final int type) throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.addEntry((LDAPDirectoryEntry) i, type);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Adds new value to a directory entry attribute. by default, this method check if the attribute
     * value already exists. If the attribute value already exists, do not make any update, and not
     * throw any Exception in this case
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param attribute
     *            Attribute name
     * @param value
     *            Attribute value
     * @exception DirectoryException
     */
    public void addIdentityAttribute(final String DN, final String attribute, final Object value)
            throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.addEntryAttribute(DN, attribute, value);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Adds new value to a directory entry attribute, but no check if this value already exists
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param attribute
     *            Attribute name
     * @param value
     *            Attribute value
     * @exception DirectoryException
     */
    public void addIdentityAttributeWithoutCheck(final String DN, final String attribute, final Object value)
            throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.addEntryAttributeWithoutCheck(DN, attribute, value);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Change the entry Distnguished Name
     * 
     * @param oldDN
     *            actual Distinguished Name of the entry
     * @param newDN
     *            new Distinguished Name of the entry
     * @exception DirectoryException
     */
    public void changeIdentity(final String oldDN, final String newDN) throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.changeEntry(oldDN, newDN);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Check if an entry exists, looking for his Distinguished Name
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @exception DirectoryException
     */
    public boolean checkIdentity(final String DN) throws DirectoryException {
        try {
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, baseDN);
            return directoryReader.checkEntry(DN);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Check if an entry has specific attribute value. This method is more efficient than getting a
     * complete <code>DirectoryEntry</code> and check the value
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param attribute
     *            Attribute name
     * @param value
     *            Attribute value
     * @exception DirectoryException
     */
    public boolean checkIdentityAttribute(final String DN, final String attribute, final Object value)
            throws DirectoryException {
        try {
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, baseDN);
            return directoryReader.checkEntryAttribute(DN, attribute, value);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Check efficiently if some query finally got some results or not
     * 
     * @param q
     *            DirectoryQuery
     * @exception DirectoryException
     */
    public boolean checkSearch(final LDAPDirectoryQuery q) throws DirectoryException {
        try {
            LDAPDirectoryReader _lq = new LDAPDirectoryReader(ldapConnection, baseDN);
            return _lq.checkSearch(q);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Disconnect from directory server
     * 
     * @exception DirectoryException
     */
    public void closeConnection() throws DirectoryException {
        try {
            ldapConnection.disconnect();
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    public String getBaseDN() {
        return baseDN;
    }

    /**
     * Get some entry from directory using his Distinguished Name
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @return DirectoryEntry
     * @exception DirectoryException
     */
    public Identity getIdentity(final String DN) throws DirectoryException {
        try {
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, baseDN);
            return directoryReader.getEntry(DN);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Gets an entry from directory using his Distinguished Name. You can provide a list of
     * attributes to be ignored when load the entry data
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param ignore_attributes
     *            You can indicate here a list of attribute to be ignored when load all entry data.
     *            this is useful if you have some big data in some attributes and do you want to
     *            ignore that
     * @return DirectoryEntry
     * @exception DirectoryException
     */
    public Identity getIdentity(final String DN, final List<String> ignore_attributes) throws DirectoryException {
        try {
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, baseDN);
            return directoryReader.getEntry(DN, ignore_attributes);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Gets an entry from directory using his Distinguished Name. You can provide a list of
     * attributes to be ignored when load the entry data. Look for attribute matches using a map of
     * values
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param ignore_attributes
     *            You can indicate here a list of attribute to be ignored when load all entry data.
     *            this is useful if you have some big data in some attributes and do you want to
     *            ignore that
     * @param attribute_matches
     *            Map with attribute names and values to match
     * @return DirectoryEntry
     * @exception DirectoryException
     */
    public Identity getIdentity(final String DN, final List<String> ignore_attributes,
            final Map<String, String> attribute_matches) throws DirectoryException {
        try {
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, baseDN);
            return directoryReader.getEntry(DN, ignore_attributes, attribute_matches);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Gets values of an entry attribute using a Distinguished Name and the name of the attribute
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param attribute
     *            name of the attribute
     * @return List<Object>
     * @exception DirectoryException
     */
    public List<Object> getIdentityAttribute(final String DN, final String attribute) throws DirectoryException {
        try {
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, baseDN);
            return directoryReader.getEntryAttribute(DN, attribute);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Check if the directory server connection use Server Socket Layers
     * 
     */
    public boolean isSecure() {
        if (ldapConnection == null) {
            return false;
        }
        return ldapConnection.isSecure();
    }

    /**
     * Deletes an entry from directory using his Distinguished Name
     * 
     * @param ID
     *            String
     * @exception DirectoryException
     */
    public void removeIdentity(final String DN) throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.removeEntry(DN);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Deletes an attribute value from a directory entry. This is more efficient than make a
     * complete update if you only wants to do this operation
     * 
     * @param DN
     *            String
     * @param attribute
     *            String
     * @param value
     *            Object
     * @exception DirectoryException
     */
    public void removeIdentityAttribute(final String DN, final String attribute, final Object value)
            throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.removeEntryAttributeValue(DN, attribute, value);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Deletes a branch from directory using his Distinguished Name
     * 
     * @param ID
     *            String
     * @exception DirectoryException
     */
    public void removeTree(final String ID) throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.removeTree(ID);
        } catch (LDAPException e) {
            throw new DirectoryException("unknown connection error - " + e.getClass());
        }
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions
     * 
     * @param q
     *            DirectoryQuery
     * @return List<DirectoryEntry>
     * @exception DirectoryException
     */
    public List<Identity> searchIdentities(final LDAPDirectoryQuery q) throws DirectoryException {
        return searchIdentities(q, null);
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions, using an
     * specific BaseDN
     * 
     * @param q
     *            DirectoryQuery
     * @param basedn
     *            Specific baseDN to search
     * @return List<DirectoryEntry>
     * @exception DirectoryException
     */
    public List<Identity> searchIdentities(final LDAPDirectoryQuery q, String basedn) throws DirectoryException {
        try {
            if (basedn == null) {
                basedn = baseDN;
            }
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, basedn);
            return directoryReader.search(q);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions. Returns a
     * <code>java.util.List<String></code> with the Distinguished names of the entries that match
     * 
     * @param q
     *            DirectoryQuery
     * @return List<String>
     * @exception DirectoryException
     */
    public List<String> searchIdentitiesNames(final LDAPDirectoryQuery q) throws DirectoryException {
        return searchIdentitiesNames(q, null);
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions. You can
     * specify a match limit
     * 
     * @param q
     *            Query
     * @param limit
     *            An <code>Integer</code> with the limit of matches
     * @param authenticated
     *            boolean
     * @return List
     * @exception DirectoryException
     */
    public List<String> searchIdentitiesNames(final LDAPDirectoryQuery q, final Integer limit)
            throws DirectoryException {
        try {
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, baseDN);
            return directoryReader.searchDN(q, limit);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Sets the count limit (maximum number of matches)
     * 
     * @param limit
     *            An <code>Integer</code> with the limit of matches for searches
     * 
     */
    public void setCountLimit(final int limit) {
        ldapConnection.setCountLimit(limit);
    }

    /**
     * Sets the connection timeout
     * 
     * @param milliseconds
     *            An <code>Integer</code> with the number of milliseconds for timeout
     */
    public void setTimeout(final int milliseconds) {
        ldapConnection.setTimeout(milliseconds);
    }

    /**
     * Sets the scope for directory. Scope determines what you get on searches. Scope is an
     * <code>Integer</code> number that you can get using <code>LDAPConnection</code> public values
     * 
     * @param scope
     *            An <code>Integer</code> number that you can get using <code>LDAPConnection</code>
     *            public values
     */
    public void setScope(final int scope) throws DirectoryException {
        ldapConnection.setScope(scope);
    }

    /**
     * Sets if the connection must use Secure Socket Layers
     * 
     * @param value
     *            A boolean value
     */
    public void setSecure(final boolean value) throws LDAPException {
        ldapConnection.setSecure(new File(properties.getProperty("ldap.ssl.store")));
    }

    /**
     * Sets an user to bind. Not needed if you connect anonymously
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param password
     *            User password
     */
    public void setUser(final String userDN, final String password) throws LDAPException {
        ldapConnection.setUser(userDN, password);
    }

    /**
     * Defines the BaseDN
     * 
     * @param baseDN
     *            Distinguished Name of the root or branch directory
     */
    public void setBaseDN(final String baseDN) throws LDAPException {
        this.baseDN = baseDN;
    }

    /**
     * Defines if the connection must be persistent. For example in this case, connection can use a
     * pool
     * 
     * @param status
     *            A boolean value
     */
    public void setConnectionPool(final boolean status) {
        ldapConnection.setConnectionPool(status);
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions. Results
     * will be order using the values of a specific attribute
     * 
     * @param q
     *            DirectoryQuery
     * @param attribute
     *            Name of the attribute that determines the order
     * @return List<DirectoryEntry>
     * @exception DirectoryException
     */
    public List<Identity> sortedSearch(final LDAPDirectoryQuery q, final String attribute) throws DirectoryException {
        return sortedSearch(q, attribute, null);
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions. Results
     * will be order using the values of a specific attribute
     * 
     * @param q
     *            Query
     * @param attribute
     *            Name of the attribute that determines the order
     * @param baseDN
     *            Distinguished Name of the root or branch directory
     * @return List<DirectoryEntry>
     * @exception DirectoryException
     */
    public List<Identity> sortedSearch(final LDAPDirectoryQuery q, final String c, String basedn)
            throws DirectoryException {
        try {
            if (basedn == null) {
                basedn = baseDN;
            }
            LDAPDirectoryReader directoryReader = new LDAPDirectoryReader(ldapConnection, basedn);
            return directoryReader.sortedSearch(q, c);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Updates an entry into directory
     * 
     * @param e
     *            Entry
     * @param int Directory type. This can be <code>LDAPDirectoryEditor.DIRECTORY_TYPE_LDAPV3</code>
     *        or <code>LDAPDirectoryEditor.DIRECTORY_TYPE_MSAD</code>
     * @exception DirectoryException
     */
    public void updateIdentity(final Identity e) throws DirectoryException {
        updateIdentity(e, LDAPDirectoryWriter.DIRECTORY_TYPE_LDAPV3);
    }

    /**
     * Updates an entry into directory
     * 
     * @param e
     *            Entry
     * @exception DirectoryException
     */
    public void updateIdentity(final Identity i, final int type) throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.updateEntry((LDAPDirectoryEntry) i, type);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }

    /**
     * Updates an entry attribute into directory. This is more efficient than make a complete entry
     * update if you only wants to do this operation
     * 
     * @param e
     *            Entry
     * @exception DirectoryException
     */
    public void updateIdentityAttribute(final String DN, final String attribute, final Object value)
            throws DirectoryException {
        try {
            LDAPDirectoryWriter directoryWriter = new LDAPDirectoryWriter(ldapConnection);
            directoryWriter.updateEntryAttribute(DN, attribute, value);
        } catch (LDAPException e) {
            if (e.getMessage() == null) {
                throw new DirectoryException("unknown connection error - " + e.getClass());
            }
            throw new DirectoryException(e.getMessage());
        }
    }
}