/*
 * LDAPDirectoryWriter class
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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.naming.Name;
import javax.naming.NameClassPair;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;

/**
 * LDAP editor for directory entries
 * 
 * @author: Ricardo Lorenzo
 * @version 0.1
 */
public class LDAPDirectoryWriter {
    public final static int DIRECTORY_TYPE_LDAPV3 = 1;
    public final static int DIRECTORY_TYPE_MSAD = 2;
    public static final int MSAD_UF_ACCOUNTDISABLE = 0x00000002;
    public static final int MSAD_UF_PASSWD_NOTREQD = 0x00000020;
    public static final int MSAD_UF_PASSWD_CANT_CHANGE = 0x00000040;
    public static final int MSAD_UF_NORMAL_ACCOUNT = 0x00000200;
    public static final int MSAD_UF_DONT_EXPIRE_PASSWD = 0x00010000;
    public static final int MSAD_UF_PASSWORD_EXPIRED = 0x00800000;
    private final static Logger _log = Logger.getLogger(LDAPDirectoryWriter.class.getName());
    private static final int GROUP_TYPE_GLOBAL_GROUP = 0x0002;
    @SuppressWarnings("unused")
    private static final int GROUP_TYPE_DOMAIN_LOCAL_GROUP = 0x0004;
    @SuppressWarnings("unused")
    private static final int GROUP_TYPE_LOCAL_GROUP = 0x0004;
    @SuppressWarnings("unused")
    private static final int GROUP_TYPE_UNIVERSAL_GROUP = 0x0008;
    private static final int GROUP_TYPE_SECURITY_ENABLED = 0x80000000;
    private static final List<String> MSAD_ATTRIBUTES;
    private LDAPConnection connection;

    static {
        MSAD_ATTRIBUTES = new ArrayList<String>();
        MSAD_ATTRIBUTES.add("givenname");
        MSAD_ATTRIBUTES.add("sn");
        MSAD_ATTRIBUTES.add("samaccountname");
        MSAD_ATTRIBUTES.add("description");
        MSAD_ATTRIBUTES.add("title");
        MSAD_ATTRIBUTES.add("postalcode");
        MSAD_ATTRIBUTES.add("street");
        MSAD_ATTRIBUTES.add("streetaddress");
        MSAD_ATTRIBUTES.add("mail");
        MSAD_ATTRIBUTES.add("l");
        MSAD_ATTRIBUTES.add("st");
        MSAD_ATTRIBUTES.add("c");
        MSAD_ATTRIBUTES.add("physicaldeliveryofficename");
        MSAD_ATTRIBUTES.add("telephonenumber");
        MSAD_ATTRIBUTES.add("facsimiletelephonenumber");
        MSAD_ATTRIBUTES.add("otherfacsimiletelephonenumber");
        MSAD_ATTRIBUTES.add("mobile");
        MSAD_ATTRIBUTES.add("pager");
        MSAD_ATTRIBUTES.add("otherpager");
        MSAD_ATTRIBUTES.add("iphone");
        MSAD_ATTRIBUTES.add("otheriphone");
        MSAD_ATTRIBUTES.add("company");
        MSAD_ATTRIBUTES.add("department");
        MSAD_ATTRIBUTES.add("homedirectory");
        MSAD_ATTRIBUTES.add("homedrive");
        MSAD_ATTRIBUTES.add("profilepath");
        MSAD_ATTRIBUTES.add("scriptpath");
        MSAD_ATTRIBUTES.add("homephone");
        MSAD_ATTRIBUTES.add("comment");
        MSAD_ATTRIBUTES.add("manager");
        MSAD_ATTRIBUTES.add("employeeid");
        MSAD_ATTRIBUTES.add("employeetype");
        MSAD_ATTRIBUTES.add("useraccountcontrol");
        MSAD_ATTRIBUTES.add("extensionattribute1");
        MSAD_ATTRIBUTES.add("extensionattribute2");
        MSAD_ATTRIBUTES.add("extensionattribute3");
        MSAD_ATTRIBUTES.add("extensionattribute4");
        MSAD_ATTRIBUTES.add("extensionattribute5");
        MSAD_ATTRIBUTES.add("extensionattribute6");
        MSAD_ATTRIBUTES.add("extensionattribute7");
        MSAD_ATTRIBUTES.add("extensionattribute8");
        MSAD_ATTRIBUTES.add("extensionattribute9");
        MSAD_ATTRIBUTES.add("extensionattribute10");
        MSAD_ATTRIBUTES.add("extensionattribute11");
        MSAD_ATTRIBUTES.add("extensionattribute12");
        MSAD_ATTRIBUTES.add("extensionattribute13");
        MSAD_ATTRIBUTES.add("extensionattribute14");
        MSAD_ATTRIBUTES.add("extensionattribute15");
        MSAD_ATTRIBUTES.add("extensionattribute16");
        MSAD_ATTRIBUTES.add("extensionattribute17");
        MSAD_ATTRIBUTES.add("extensionattribute18");
        MSAD_ATTRIBUTES.add("extensionattribute19");
        MSAD_ATTRIBUTES.add("extensionattribute20");
        MSAD_ATTRIBUTES.add("extensionattribute21");
        MSAD_ATTRIBUTES.add("extensionattribute22");
        MSAD_ATTRIBUTES.add("extensionattribute23");
        MSAD_ATTRIBUTES.add("extensionattribute24");
        MSAD_ATTRIBUTES.add("extensionattribute1");
        MSAD_ATTRIBUTES.add("extensionattribute1");
        MSAD_ATTRIBUTES.add("extensionattribute1");
        MSAD_ATTRIBUTES.add("homemdb");
        MSAD_ATTRIBUTES.add("homemta");
        MSAD_ATTRIBUTES.add("legacyexchangedn");
        MSAD_ATTRIBUTES.add("mailnickname");
        MSAD_ATTRIBUTES.add("mdbusedefaults");
        MSAD_ATTRIBUTES.add("msexchhomeservername");
        MSAD_ATTRIBUTES.add("msexchversion");
        MSAD_ATTRIBUTES.add("msexchmailboxguid");
        MSAD_ATTRIBUTES.add("msexchrecipientdisplaytype");
        MSAD_ATTRIBUTES.add("msexchrecipienttypedetails");
        MSAD_ATTRIBUTES.add("msexchhidefromaddresslists");
        MSAD_ATTRIBUTES.add("msexchpoliciesincluded");
        MSAD_ATTRIBUTES.add("msexchpoliciesexcluded");
        MSAD_ATTRIBUTES.add("proxyaddresses");
        MSAD_ATTRIBUTES.add("pwdLastSet");
        MSAD_ATTRIBUTES.add("lockouttime");
        MSAD_ATTRIBUTES.add("homepostaladdress");
    }

    /**
     * LDAPDirectoryEditor constructor
     * 
     * @param connection
     *            LDAPConnection
     * @param baseDN
     *            String
     */
    public LDAPDirectoryWriter(final LDAPConnection connection) {
        this.connection = connection;
    }

    /**
     * Adds an entry to the directory. By default use a directory type
     * <code>LDAPDirectoryEditor.DIRECTORY_TYPE_LDAPV3</code>.
     * 
     * @param entry
     *            LDAPDirectoryEntry
     * @exception LDAPException
     */
    public void addEntry(final LDAPDirectoryEntry entry) throws LDAPException {
        addEntry(entry, DIRECTORY_TYPE_LDAPV3);
    }

    /**
     * Adds an entry to the directory
     * 
     * @param entry
     *            LDAPDirectoryEntry
     * @param int Directory type. This can be <code>LDAPDirectoryEditor.DIRECTORY_TYPE_LDAPV3</code>
     *        or <code>LDAPDirectoryEditor.DIRECTORY_TYPE_MSAD</code>
     * @exception LDAPException
     */
    public void addEntry(final LDAPDirectoryEntry entry, final int type) throws LDAPException {
        switch (type) {
            case DIRECTORY_TYPE_LDAPV3: {
                addEntryLDAPv3(entry);
                break;
            }
            case DIRECTORY_TYPE_MSAD: {
                addEntryMSAD(entry);
                break;
            }
            default:
                throw new LDAPException("Invalid directory type");
        }
    }

    private void addEntryLDAPv3(final LDAPDirectoryEntry entry) throws LDAPException {
        try {
            DirContext ctx = connection.connect(LDAPConnection.RW);
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }
            Attributes attrs = new BasicAttributes(true);
            Map<String, Object[]> hma = entry.getAttributes();
            for (String name : entry.getAttributeNames()) {
                if (hma.get(name) == null) {
                    continue;
                }
                Attribute ba = new BasicAttribute(name);
                if (hma.get(name) instanceof Object[]) {
                    for (Object attribute : hma.get(name)) {
                        ba.add(attribute);
                    }
                } else {
                    ba.add(hma.get(name));
                }
                attrs.put(ba);
            }
            ctx.bind(entry.getID(), null, attrs);
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "addEntryLDAPv3() nullpointer");
            throw new LDAPException("add entry null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "addEntryLDAPv3() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    private void addEntryMSAD(final LDAPDirectoryEntry entry) throws LDAPException {
        try {
            DirContext _ctx = connection.connect(LDAPConnection.RW);
            if (_ctx == null) {
                throw new LDAPException("directory service not available");
            }
            String _password = null;
            Attributes _attrs = new BasicAttributes(true);
            Map<String, Object[]> hma = entry.getAttributes();
            for (String name : entry.getAttributeNames()) {
                if (hma.get(name) == null || name.toLowerCase().equals("unicodepwd")
                        || name.toLowerCase().equals("userpassword")) {
                    continue;
                }
                Attribute _ba = new BasicAttribute(name);
                for (Object attribute : hma.get(name)) {
                    if (attribute == null) {
                        continue;
                    }
                    if (attribute instanceof String && ((String) attribute).isEmpty()) {
                        continue;
                    }
                    _ba.add(attribute);
                }
                if (_ba.size() > 0) {
                    _attrs.put(_ba);
                }
            }
            if (_attrs.get("objectclass").contains("user") && _attrs.get("userAccountControl") == null) {
                _attrs.put(new BasicAttribute("userAccountControl", Integer.toString(MSAD_UF_NORMAL_ACCOUNT
                        + MSAD_UF_PASSWD_NOTREQD + MSAD_UF_DONT_EXPIRE_PASSWD)));
            } else if (_attrs.get("objectclass").contains("group")) {
                _attrs.put("groupType", Integer.toString(GROUP_TYPE_SECURITY_ENABLED + GROUP_TYPE_GLOBAL_GROUP));
            }

            _ctx.bind(entry.getID(), null, _attrs);
            try {
                if (hma.containsKey("unicodepwd")) {
                    Object[] _value = hma.get("unicodepwd");
                    _password = String.valueOf(_value[0]);
                } else if (hma.containsKey("userpassword")) {
                    Object[] _value = hma.get("userpassword");
                    _password = String.valueOf(_value[0]);
                }
                if (_password != null && !_password.isEmpty()) {
                    ModificationItem[] _mods = new ModificationItem[1];
                    _mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("unicodePwd",
                            encodePasswordForMSAD(_password)));
                    if (hma.containsKey("pwdlastset") && "0".equals(hma.get("pwdlastset")[0])) {
                        _mods = new ModificationItem[2];
                        _mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("unicodePwd",
                                encodePasswordForMSAD(_password)));
                        _mods[1] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("pwdLastSet",
                                hma.get("pwdlastset")[0]));
                    }
                    _ctx.modifyAttributes(entry.getID(), _mods);
                }
            } catch (NamingException e) {
                _ctx.unbind(entry.getID());
                _log.log(java.util.logging.Level.ALL, "addEntryMSAD() - " + e.getMessage());
                throw new LDAPException("cannot set user password - " + e.getMessage());
            } catch (UnsupportedEncodingException e) {
                _log.log(java.util.logging.Level.ALL, "addEntryMSAD() - " + e.getMessage());
                throw new LDAPException("cannot set user password - " + e.getMessage());
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "addEntryMSAD() nullpointer");
            throw new LDAPException("LDAPEditor.addEntryMSAD() nullpointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "addEntryMSAD() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Adds an attribute to an entry on the directory efficiently. This method is more efficient
     * than update the entire entry
     * 
     * @param entry
     *            LDAPDirectoryEntry
     * @exception LDAPException
     */
    public void addEntryAttribute(final String DN, final String attribute, final Object value) throws LDAPException {
        try {
            if (DN == null || DN.isEmpty()) {
                throw new LDAPException("invalid entry DN");
            }
            if (attribute == null || attribute.isEmpty()) {
                throw new LDAPException("invalid attribute name");
            }
            if (value == null) {
                throw new LDAPException("invalid attribute value");
            }
            DirContext ctx = connection.connect(LDAPConnection.RW);
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }

            int _mode = -1;
            Attributes _atts = ctx.getAttributes(DN, new String[] { attribute });
            Attribute _att;
            if (_atts != null) {
                _att = _atts.get(attribute);
                if (_att == null) {
                    _att = new BasicAttribute(attribute, true);
                    _mode = DirContext.ADD_ATTRIBUTE;
                } else {
                    _mode = DirContext.REPLACE_ATTRIBUTE;
                }
            } else {
                _att = new BasicAttribute(attribute);
                _mode = DirContext.ADD_ATTRIBUTE;
            }
            if (value instanceof Object[]) {
                for (Object o : (Object[]) value) {
                    if (!_att.contains(o)) {
                        _att.add(o);
                    }
                }
            } else {
                if (!_att.contains(value)) {
                    _att.add(value);
                }
            }
            if (_att.size() > 0) {
                ctx.modifyAttributes(DN, new ModificationItem[] { new ModificationItem(_mode, _att) });
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "addEntryAttribute() null pointer");
            throw new LDAPException("add entry attribute null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "addEntryAttribute() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Adds an attribute to an entry in the directory efficiently
     * 
     * @param entry
     *            LDAPEntry
     * @exception LDAPException
     */
    public void addEntryAttributeWithoutCheck(final String DN, final String attribute, final Object value)
            throws LDAPException {
        try {
            if (DN == null || DN.isEmpty()) {
                throw new LDAPException("invalid entry DN");
            }
            if (attribute == null || attribute.isEmpty()) {
                throw new LDAPException("invalid attribute name");
            }
            if (value == null) {
                throw new LDAPException("invalid attribute value");
            }
            DirContext ctx = connection.connect(LDAPConnection.RW);
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }

            Attribute _att = new BasicAttribute(attribute, true);
            if (value instanceof Object[]) {
                for (Object o : (Object[]) value) {
                    if (!_att.contains(o)) {
                        _att.add(o);
                    }
                }
            } else {
                if (!_att.contains(value)) {
                    _att.add(value);
                }
            }
            if (_att.size() > 0) {
                ctx.modifyAttributes(DN,
                        new ModificationItem[] { new ModificationItem(DirContext.ADD_ATTRIBUTE, _att) });

            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "addEntryAttributeWithoutCheck() null pointer");
            throw new LDAPException("add entry attribute null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "addEntryAttributeWithoutCheck() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Modify Distinguished name of an entry
     * 
     * @param entry
     *            LDAPEntry
     * @exception LDAPException
     */
    public void changeEntry(final String oldDN, final String newDN) throws LDAPException {
        try {
            DirContext _ctx = null;
            try {
                _ctx = connection.connect(LDAPConnection.RW);
            } catch (LDAPException e) {
                // nothing
            }
            if (_ctx == null) {
                throw new LDAPException("directory service not available");
            }
            _ctx.rename(oldDN, newDN);
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "changeEntry() null pointer");
            throw new LDAPException("change entry null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "changeEntry() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    private static final boolean compare(final Object _a, final Object _b) {
        if (_a == null && _b == null) {
            return false;
        }
        if (_a.equals(_b)) {
            return true;
        }
        if (_a instanceof Object[] && _b instanceof Object[]) {
            if (((Object[]) _a).length != ((Object[]) _b).length || ((Object[]) _b).length == 0) {
                return false;
            }
            for (int x = 0; x < ((Object[]) _b).length; x++) {
                if (((Object[]) _a)[x] instanceof String && ((Object[]) _b)[x] instanceof String) {
                    if (!(((String) ((Object[]) _a)[x]).equalsIgnoreCase((String) ((Object[]) _b)[x]))) {
                        return false;
                    }
                } else if (!((Object[]) _a)[x].equals(((Object[]) _b)[x])) {
                    return false;
                }
            }
            return true;
        }
        if (_a instanceof Object[]) {
            if (((Object[]) _a).length > 1) {
                return false;
            }
            if (((Object[]) _a)[0] instanceof String && _b instanceof String) {
                if (((String) ((Object[]) _a)[0]).equalsIgnoreCase((String) _b)) {
                    return true;
                } else {
                    return false;
                }
            } else if (((Object[]) _a)[0].equals(_b)) {
                return true;
            }
        }
        if (_b instanceof Object[]) {
            if (((Object[]) _b).length > 1) {
                return false;
            }
            if (((Object[]) _b)[0] instanceof String && _a instanceof String) {
                if (((String) ((Object[]) _b)[0]).equalsIgnoreCase((String) _a)) {
                    return true;
                } else {
                    return false;
                }
            } else if (((Object[]) _b)[0].equals(_a)) {
                return true;
            }
        }
        return false;
    }

    private static byte[] encodePasswordForMSAD(final String password) throws java.io.UnsupportedEncodingException {
        String _password = "\"" + password + "\"";
        return _password.getBytes("UTF-16LE");
    }

    /**
     * Verify if an entry has an specific attribute value
     * 
     * @param DN
     *            String
     * @param attribute
     *            String
     * @param value
     *            Object
     * @exception LDAPException
     */
    public boolean hasEntryAttributeValue(final String DN, final String attribute, final Object value)
            throws LDAPException {
        try {
            if (DN == null || DN.isEmpty()) {
                throw new LDAPException("invalid entry DN");
            }
            if (attribute == null || attribute.isEmpty()) {
                throw new LDAPException("invalid attribute name");
            }
            if (value == null) {
                return false;
            }
            DirContext ctx = connection.connect(LDAPConnection.RW);
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }

            Attributes _atts = ctx.getAttributes(DN, new String[] { attribute });
            if (_atts == null) {
                return false;
            }
            Attribute _att = _atts.get(attribute);
            if (_att == null) {
                return false;
            }
            return _att.contains(value);
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "hasEntryAttributeValue() null pointer");
            throw new LDAPException("has entry attribute value null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "hasEntryAttributeValue() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Remove a branch from directory, including all entries
     * 
     * @param DN
     *            String
     * @exception LDAPException
     */
    public void removeTree(final String DN) throws LDAPException {
        try {
            DirContext ctx = connection.connect(LDAPConnection.RW);
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }

            NamingEnumeration<NameClassPair> _ne = null;
            try {
                NameParser parser = ctx.getNameParser("");
                Name _n = parser.parse(scapeSlashes(DN));
                _ne = ctx.list(_n);
            } finally {
                connection.disconnect();
            }

            if (_ne != null) {
                while (_ne.hasMoreElements()) {
                    NameClassPair _child = _ne.next();
                    removeTree(_child.getName() + "," + DN);
                }
            }
            removeEntry(DN);
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "removeTree() null pointer");
            throw new LDAPException("remove tree null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "removeTree() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        }
    }

    /**
     * Remove an entry from directory
     * 
     * @param DN
     *            String Distinguished Name
     * @exception LDAPException
     */
    public void removeEntry(final String DN) throws LDAPException {
        try {
            DirContext ctx = connection.connect(LDAPConnection.RW);
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }

            NameParser parser = ctx.getNameParser("");
            Name _n = parser.parse(DN);
            ctx.unbind(_n);
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "removeEntry() null pointer");
            throw new LDAPException("remove entry null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "removeEntry() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Remove an attribute value from an entry on a directory
     * 
     * @param DN
     *            String
     * @param attribute
     *            String
     * @param value
     *            Object
     * @exception LDAPException
     */
    public void removeEntryAttributeValue(final String DN, final String attribute, final Object value)
            throws LDAPException {
        try {
            if (DN == null || DN.isEmpty()) {
                throw new LDAPException("invalid entry DN");
            }
            if (attribute == null || attribute.isEmpty()) {
                throw new LDAPException("invalid attribute name");
            }
            if (value == null) {
                throw new LDAPException("invalid attribute value");
            }
            DirContext ctx = connection.connect(LDAPConnection.RW);
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }

            Attributes _atts = ctx.getAttributes(DN, new String[] { attribute });
            if (_atts == null) {
                throw new LDAPException("attribute [" + attribute + "] not found in entry");
            }
            Attribute _att = _atts.get(attribute);
            if (_att == null) {
                throw new LDAPException("attribute [" + attribute + "] not found in entry");
            }
            /*
             * if(!_att.contains(value)) { throw new LDAPException("attribute [" + attribute +
             * "] not found in entry"); }
             */

            ctx.modifyAttributes(DN, new ModificationItem[] { new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
                    new BasicAttribute(attribute, value)) });
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "removeEntryAttributeValue() null pointer");
            throw new LDAPException("remove entry attribute null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "removeEntryAttributeValue() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Makes an entry update on directory
     * 
     * @param entry
     *            LDAPDirectoryEntry
     * @exception LDAPException
     */
    public void updateEntry(final LDAPDirectoryEntry entry) throws LDAPException {
        updateEntry(entry, DIRECTORY_TYPE_LDAPV3);
    }

    /**
     * Makes an entry update on directory
     * 
     * @param entry
     *            LDAPDirectoryEntry
     * @param int Directory type. This can be <code>LDAPDirectoryEditor.DIRECTORY_TYPE_LDAPV3</code>
     *        or <code>LDAPDirectoryEditor.DIRECTORY_TYPE_MSAD</code>
     * @exception LDAPException
     */
    public void updateEntry(final LDAPDirectoryEntry entry, final int type) throws LDAPException {
        switch (type) {
            case DIRECTORY_TYPE_LDAPV3: {
                updateEntryLDAPv3(entry);
                break;
            }
            case DIRECTORY_TYPE_MSAD: {
                updateEntryMSAD(entry);
                break;
            }
            default:
                break;
        }
    }

    /**
     * Update an attribute of an entry on a directory
     * 
     * @param entry
     *            LDAPEntry
     * @exception LDAPException
     */
    public void updateEntryAttribute(final String DN, final String attribute, final Object value) throws LDAPException {
        try {
            if (DN == null || DN.isEmpty()) {
                throw new LDAPException("invalid entry DN");
            }
            if (attribute == null || attribute.isEmpty()) {
                throw new LDAPException("invalid attribute name");
            }
            if (value == null) {
                throw new LDAPException("invalid attribute value");
            }
            DirContext ctx = connection.connect(LDAPConnection.RW);
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }

            int _mode = -1;
            Attributes _atts = ctx.getAttributes(DN, new String[] { attribute });
            Attribute _att;
            if (_atts != null) {
                _att = _atts.get(attribute);
                if (_att == null) {
                    _att = new BasicAttribute(attribute, true);
                    _mode = DirContext.ADD_ATTRIBUTE;
                } else {
                    _mode = DirContext.REPLACE_ATTRIBUTE;
                }
            } else {
                _att = new BasicAttribute(attribute);
                _mode = DirContext.ADD_ATTRIBUTE;
            }

            _att = new BasicAttribute(attribute, true);
            if (value instanceof Object[]) {
                for (Object o : (Object[]) value) {
                    if (!_att.contains(o)) {
                        _att.add(o);
                    }
                }
            } else {
                if (!_att.contains(value)) {
                    _att.add(value);
                }
            }
            if (_att.size() > 0) {
                ctx.modifyAttributes(DN, new ModificationItem[] { new ModificationItem(_mode, _att) });
            } else {
                _mode = DirContext.REMOVE_ATTRIBUTE;
                ctx.modifyAttributes(DN, new ModificationItem[] { new ModificationItem(_mode, _att) });
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "updateEntryAttribute() null pointer");
            throw new LDAPException("update entry attribute() null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "updateEntryAttribute() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    private void updateEntryLDAPv3(final LDAPDirectoryEntry entry) throws LDAPException {
        try {
            DirContext _ctx = null;
            if (entry != null && entry.getAttribute("modifytimestamp") != null) {
                entry.removeAttribute("modifytimestamp");
            }
            try {
                _ctx = connection.connect(LDAPConnection.RW);
            } catch (LDAPException e) {
                // nothing
            }
            if (_ctx == null) {
                throw new LDAPException("directory service not available");
            }
            Attributes attrs = _ctx.getAttributes(entry.getID());
            @SuppressWarnings("unchecked")
            NamingEnumeration<Attribute> ne = (NamingEnumeration<Attribute>) attrs.getAll();
            Map<String, Object[]> hma = entry.getAttributes();
            List<ModificationItem> _mods = new ArrayList<ModificationItem>();
            while (ne.hasMore()) {
                Attribute att = ne.next();
                if (hma.containsKey(att.getID().toLowerCase())) {
                    if (hma.get(att.getID().toLowerCase()) == null) {
                        continue;
                    }
                    BasicAttribute ba = new BasicAttribute(att.getID());
                    Object[] _actualValues = new Object[att.size()];
                    for (int x = 0; x < att.size(); x++) {
                        _actualValues[x] = att.get(x);
                    }
                    Object[] _value = hma.get(att.getID().toLowerCase());
                    if (compare(_value, _actualValues) && !"gidnumber".equals(att.getID().toLowerCase())) {
                        hma.remove(att.getID().toLowerCase());
                        continue;
                    }
                    if (hma.get(att.getID().toLowerCase()) instanceof Object[]) {
                        for (Object o : hma.remove(att.getID().toLowerCase())) {
                            ba.add(o);
                        }
                    } else {
                        ba.add(hma.remove(att.getID().toLowerCase()));
                    }
                    _mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, ba));
                } else {
                    _mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(att.getID())));
                }
            }
            for (String name : hma.keySet()) {
                if (hma.get(name) == null) {
                    continue;
                }
                BasicAttribute ba = new BasicAttribute(name);
                for (Object o : hma.get(name)) {
                    ba.add(o);
                }
                _mods.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, ba));
            }
            ModificationItem[] mods = new ModificationItem[_mods.size()];
            for (int j = _mods.size(); --j >= 0;) {
                mods[j] = _mods.get(j);
            }
            if (!_mods.isEmpty()) {
                _ctx.modifyAttributes(entry.getID(), mods);
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "updateEntryLDAPv3() null pointer");
            throw new LDAPException("update entry null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "updateEntryLDAPv3() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    private void updateEntryMSAD(final LDAPDirectoryEntry entry) throws LDAPException {
        try {
            DirContext _ctx = null;
            try {
                _ctx = connection.connect(LDAPConnection.RW);
            } catch (LDAPException e) {
            }
            if (_ctx == null) {
                throw new LDAPException("directory service not available");
            }

            Attributes attrs = _ctx.getAttributes(entry.getID());
            @SuppressWarnings("unchecked")
            NamingEnumeration<Attribute> ne = (NamingEnumeration<Attribute>) attrs.getAll();
            Map<String, Object[]> hma = entry.getAttributes();
            List<ModificationItem> _mods = new ArrayList<ModificationItem>();
            while (ne.hasMore()) {
                Attribute att = ne.next();
                if (hma.containsKey(att.getID().toLowerCase())) {
                    if (MSAD_ATTRIBUTES.contains(att.getID().toLowerCase())) {
                        Object[] _value = hma.remove(att.getID().toLowerCase());
                        if (!compare(_value, att.get())) {
                            BasicAttribute ba = new BasicAttribute(att.getID());
                            if ("telephonenumber".equals(att.getID().toLowerCase())) {
                                ba.add((_value[0] == "" || "null".equals(_value[0])) ? " " : _value[0]);
                            } else {
                                for (int j = 0; j < _value.length; j++) {
                                    ba.add((_value[j] == "" || "null".equals(_value[j])) ? " " : _value[j]);
                                }
                            }
                            _mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, ba));
                        }
                    }
                } else {
                    _mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(att.getID())));
                }
            }
            for (String name : hma.keySet()) {
                if (hma.get(name) == null) {
                    continue;
                }

                if (name.toLowerCase().equals("unicodepwd")) {
                    try {
                        Object[] _value = hma.get(name);
                        ModificationItem _mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(
                                "unicodePwd", encodePasswordForMSAD(String.valueOf(_value[0]))));
                        _ctx.modifyAttributes(entry.getID(), new ModificationItem[] { _mod });
                        continue;
                    } catch (NamingException e) {
                        _ctx.unbind(entry.getID());
                        _log.log(java.util.logging.Level.ALL, "updateEntryMSAD() - " + e.getMessage());
                        throw new LDAPException("cannot set user password - " + e.getMessage());
                    } catch (UnsupportedEncodingException e) {
                        _log.log(java.util.logging.Level.ALL, "updateEntryMSAD() - " + e.getMessage());
                        throw new LDAPException("cannot set user password - " + e.getMessage());
                    }
                }

                BasicAttribute att = new BasicAttribute(name);
                if (MSAD_ATTRIBUTES.contains(att.getID().toLowerCase())) {
                    if ("telephonenumber".equals(att.getID().toLowerCase())) {
                        att.add(hma.get(name)[0]);
                    } else {
                        for (Object o : hma.get(name)) {
                            att.add(o);
                        }
                    }
                    _mods.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, att));
                }
            }
            if (_mods.size() > 0) {
                _ctx.modifyAttributes(entry.getID(), _mods.toArray(new ModificationItem[_mods.size()]));
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "updateEntryMSAD() null pointer");
            throw new LDAPException("update entry null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "updateEntryMSAD() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    private static final String scapeSlashes(final String text) {
        int offset = 0;
        StringBuilder _sb = new StringBuilder(text);

        while ((offset = _sb.indexOf("/", offset)) != -1) {
            _sb.insert(offset, "\\");
            offset = offset + 2;
        }
        return _sb.toString();
    }
}