/*
 * LDAPDirectoryReader class
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

import java.io.IOException;
import java.text.Collator;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.SortControl;

import com.ricardolorenzo.identity.Identity;

/**
 * Runs LDAP queries against a directory server
 * 
 * @author: Ricardo Lorenzo
 * @version 0.1
 */
public class LDAPDirectoryReader {
    private final static Logger _log = Logger.getLogger(LDAPDirectoryReader.class.getName());
    private LDAPConnection connection;
    private String baseDN;

    /**
     * LDAPDirectoryQuery constructor
     * 
     * @param connection
     *            LDAPConnection
     * @param baseDN
     *            String
     */
    public LDAPDirectoryReader(final LDAPConnection connection, final String baseDN) {
        this.connection = connection;
        this.baseDN = baseDN;
    }

    /**
     * Verify if an entry Distinguished Name already exists on directory
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @return boolean
     * @exception LDAPException
     */
    public boolean checkEntry(final String DN) throws LDAPException {
        try {
            DirContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }
            if (ctx.getAttributes(DN) != null) {
                return true;
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "checkEntry() null pointer");
            throw new LDAPException("add entry null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "checkEntry() - " + e.getMessage());
            throw new LDAPException(e.getMessage());

        } finally {
            connection.disconnect();
        }
        return false;
    }

    /**
     * Check if an entry has specific attribute value. This method is more efficient than getting a
     * complete <code>LDAPDirectoryEntry</code> and check the value
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param attribute
     *            Attribute name
     * @param value
     *            Attribute value
     * @return boolean
     * @exception LDAPException
     */
    public boolean checkEntryAttribute(final String DN, final String attribute, final Object value)
            throws LDAPException {
        try {
            DirContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }

            Object[] _values;
            StringBuilder _sb = new StringBuilder();
            if (value instanceof Object[]) {
                _values = (Object[]) value;
                if (_values.length > 1) {
                    _sb.append("(&");
                }
                for (int i = 0; i < _values.length; i++) {
                    _sb.append("(");
                    _sb.append(attribute);
                    _sb.append("={");
                    _sb.append(i);
                    _sb.append("})");
                }
                if (_values.length > 1) {
                    _sb.append(")");
                }
            } else {
                _sb.append("(");
                _sb.append(attribute);
                _sb.append("={0})");
                _values = new Object[] { value };
            }

            SearchControls ctls = new SearchControls();
            ctls.setReturningAttributes(new String[0]);
            ctls.setSearchScope(SearchControls.OBJECT_SCOPE);

            NamingEnumeration<SearchResult> _answer = ctx.search(DN, _sb.toString(), _values, ctls);
            return _answer.hasMoreElements();
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "checkEntryAttribute() null pointer");
            throw new LDAPException("check entry null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "checkEntryAttribute() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Check efficiently if some query finally got some results or not
     * 
     * @param q
     *            DirectoryQuery
     * @return boolean
     * @exception LDAPException
     */
    public boolean checkSearch(final LDAPDirectoryQuery q) throws LDAPException {
        try {
            DirContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }
            SearchControls ctls = new SearchControls();
            ctls.setCountLimit(2);
            ctls.setSearchScope(connection.getScope());

            String filter = getQueryString(ctx, q);
            NamingEnumeration<SearchResult> answer = ctx.search(baseDN, filter, ctls);
            return answer.hasMoreElements();
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "checkSearch() null pointer");
            throw new LDAPException("check search nullpointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "checkSearch() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    private final static String getConditionFilter(final Object[] _condition) throws LDAPException {
        StringBuilder filter = new StringBuilder();
        int type = ((Integer) _condition[0]).intValue();
        String value = String.valueOf(_condition[2]), condition = String.valueOf(_condition[1]);
        if (type == LDAPDirectoryQuery.STARTS_WITH && !value.equals("*")) {
            value += "*";
        } else if (type == LDAPDirectoryQuery.ENDS_WITH && !value.equals("*")) {
            value = "*" + value;
        } else if ((type == LDAPDirectoryQuery.NOT_CONTAINS || type == LDAPDirectoryQuery.CONTAINS)
                && !value.equals("*")) {
            value = "*" + value + "*";
        }
        if (type == LDAPDirectoryQuery.NOT_EXACT || type == LDAPDirectoryQuery.NOT_CONTAINS) {
            filter.append("(!");
        }
        filter.append("(");
        if (condition.contains(":")) {
            if (!condition.matches("[a-zA-Z0-9]+:[a-zA-Z0-9]+:")) {
                throw new LDAPException("invalid query condition");
            }
            filter.append(condition);
        } else {
            filter.append(condition);
        }
        if (type == LDAPDirectoryQuery.APPROXIMATE) {
            filter.append("~");
        } else if (type == LDAPDirectoryQuery.GREATER) {
            filter.append(">");
        } else if (type == LDAPDirectoryQuery.LOWER) {
            filter.append("<");
        }
        filter.append("=");
        filter.append(value);
        filter.append(")");
        if (type == LDAPDirectoryQuery.NOT_EXACT || type == LDAPDirectoryQuery.NOT_CONTAINS) {
            filter.append(")");
        }
        return filter.toString();
    }

    private final static String getQueryFilter(final LDAPDirectoryQuery _q) throws LDAPException {
        StringBuilder filter = new StringBuilder();
        while (_q.hasMoreConditions()) {
            Object _o = _q.nextCondition();
            if (_o instanceof LDAPDirectoryQuery) {
                filter.append(getQueryFilter((LDAPDirectoryQuery) _o));
            } else if (_o instanceof Object[]) {
                filter.append(getConditionFilter((Object[]) _o));
            }
        }
        if (_q.getType() == LDAPDirectoryQuery.OR) {
            if (_q.totalConditions() > 1) {
                filter.insert(0, "(|");
                filter.append(")");
            }
        } else {
            if (_q.totalConditions() > 1) {
                filter.insert(0, "(&");
                filter.append(")");
            }
        }
        return filter.toString();
    }

    private String getQueryString(final DirContext ctx, final LDAPDirectoryQuery q) throws NamingException,
            LDAPException {
        StringBuilder filter = new StringBuilder();
        while (q.hasMoreConditions()) {
            Object _condition = q.nextCondition();
            if (_condition instanceof LDAPDirectoryQuery) {
                filter.append(getQueryFilter((LDAPDirectoryQuery) _condition));
            } else if (_condition instanceof Object[]) {
                int type = ((Integer) ((Object[]) _condition)[0]).intValue();
                String value = (String) ((Object[]) _condition)[2];
                if (type == LDAPDirectoryQuery.BRANCH) {
                    SearchControls ctls = new SearchControls();
                    ctls.setSearchScope(LDAPConnection.ONE_SCOPE);
                    NamingEnumeration<SearchResult> answer = ctx.search(baseDN, "(" + ((Object[]) _condition)[1] + "="
                            + value + ")", ctls);
                    while (answer.hasMoreElements()) {
                        SearchResult sr = answer.nextElement();
                        baseDN = sr.getName() + "," + baseDN;
                    }
                } else {
                    filter.append(getConditionFilter(((Object[]) _condition)));
                }
            }
        }
        if (q.getType() == LDAPDirectoryQuery.OR) {
            if (q.totalConditions() > 1) {
                filter.insert(0, "(|");
                filter.append(")");
            }
        } else {
            if (q.totalConditions() > 1) {
                filter.insert(0, "(&");
                filter.append(")");
            }
        }
        return filter.toString();
    }

    /**
     * Gets an <code>LDAPDirectoryEntry</code> object that represent an entry on directory
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @return LDAPDirectoryEntry
     * @exception LDAPException
     */
    public LDAPDirectoryEntry getEntry(final String DN) throws LDAPException {
        return getEntry(DN, null, null);
    }

    /**
     * Gets an <code>LDAPDirectoryEntry</code> object that represent an entry on directory. You can
     * provide a list of attributes to be ignored when load the entry data
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param ignore_attributes
     *            You can indicate here a list of attribute to be ignored when load all entry data.
     *            this is useful if you have some big data in some attributes and do you want to
     *            ignore that
     * @return LDAPDirectoryEntry
     * @exception LDAPException
     */
    public LDAPDirectoryEntry getEntry(final String DN, final List<String> ignore_attributes) throws LDAPException {
        return getEntry(DN, ignore_attributes, null);
    }

    /**
     * Gets an <code>LDAPDirectoryEntry</code> object that represent an entry on directory. You can
     * provide a list of attributes to be ignored when load the entry data. Look for attribute
     * matches using a map of values
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param ignore_attributes
     *            You can indicate here a list of attribute to be ignored when load all entry data.
     *            this is useful if you have some big data in some attributes and do you want to
     *            ignore that
     * @param attribute_matches
     *            Map with attribute names and values to match
     * @return LDAPDirectoryEntry
     * @exception LDAPException
     */
    public LDAPDirectoryEntry getEntry(final String DN, final List<String> ignore_attributes,
            final Map<String, String> attribute_matches) throws LDAPException {
        LDAPDirectoryEntry _e = null;
        try {
            _e = new LDAPDirectoryEntry(DN);
            DirContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }
            Attributes atts = ctx.getAttributes(DN);
            if (atts == null) {
                return null;
            }
            @SuppressWarnings("unchecked")
            NamingEnumeration<Attribute> ne = (NamingEnumeration<Attribute>) atts.getAll();
            while (ne.hasMore()) {
                Attribute att = ne.next();
                if (ignore_attributes == null || !ignore_attributes.contains(att.getID())) {
                    List<Object> _values = new ArrayList<Object>();
                    @SuppressWarnings("unchecked")
                    NamingEnumeration<Object> nea = (NamingEnumeration<Object>) att.getAll();
                    while (nea.hasMore()) {
                        Object _value = nea.next();
                        if (attribute_matches == null || !attribute_matches.containsKey(att.getID())) {
                            _values.add(_value);
                        } else if (attribute_matches.get(att.getID()) != null
                                && String.valueOf(_value).contains(attribute_matches.get(att.getID()))) {
                            _values.add(_value);
                        }
                    }
                    _e.setAttribute(att.getID(), _values.toArray());
                }
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "getEntry() null pointer");
            throw new LDAPException("get entry null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "getEntry() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
        return _e;
    }

    /**
     * Gets values of an entry attribute using a Distinguished Name and the name of the attribute
     * 
     * @param DN
     *            Distinguished Name of the entry
     * @param attribute
     *            name of the attribute
     * @return List<Object>
     * @exception LDAPException
     */
    public List<Object> getEntryAttribute(final String DN, final String attribute) throws LDAPException {
        List<Object> _values = new ArrayList<Object>();
        try {
            DirContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }
            Attributes _atts = null;
            if ("modifyTimestamp".equals(attribute)) {
                String[] _attributeName = new String[1];
                _attributeName[0] = attribute;
                _atts = ctx.getAttributes(DN, _attributeName);
            } else {
                _atts = ctx.getAttributes(DN);
                if (_atts == null) {
                    throw new LDAPException("entry not found [" + DN + "]");
                }
            }
            Attribute _att = _atts.get(attribute);
            if (_att == null) {
                throw new LDAPException("attribute [" + attribute + "] not found in entry");
            }

            @SuppressWarnings("unchecked")
            NamingEnumeration<Object> _ne = (NamingEnumeration<Object>) _att.getAll();
            while (_ne.hasMore()) {
                _values.add(_ne.next());
            }
            return _values;
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "getEntryAttribute() null pointer");
            throw new LDAPException("get entry attribute null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "getEntryAttribute() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions
     * 
     * @param q
     *            DirectoryQuery
     * @return List<DirectoryEntry>
     * @exception LDAPException
     */
    public List<Identity> search(final LDAPDirectoryQuery q) throws LDAPException {
        List<Identity> results = new ArrayList<Identity>();
        try {
            DirContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }
            SearchControls ctls = new SearchControls();
            List<String> _aux = new ArrayList<String>();
            _aux.add("modifyTimestamp");
            _aux.add("*");
            ctls.setReturningAttributes(_aux.toArray(new String[_aux.size()]));
            if (connection.hasCountLimit()) {
                ctls.setCountLimit(connection.getCountLimit());
            }
            ctls.setSearchScope(connection.getScope());

            String filter = getQueryString(ctx, q);
            NamingEnumeration<SearchResult> answer = ctx.search(baseDN, filter, ctls);
            while (answer.hasMoreElements()) {
                SearchResult sr = answer.nextElement();
                LDAPDirectoryEntry _e = null;
                if (sr.getName().isEmpty()) {
                    _e = new LDAPDirectoryEntry(baseDN);
                } else {
                    _e = new LDAPDirectoryEntry(sr.getNameInNamespace());
                    /*
                     * _e = new LDAPEntry(sr.getName() + "," + this.baseDN); if(_e.getID().matches(
                     * "^(ldap|ldaps)\\://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z0-9\\-]+(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\\-\\._\\?\\,\\'/\\\\\\+&amp;%\\$#\\=~])*[^\\.\\,\\)\\(\\s]$"
                     * )) { URL _url = new URL(_e.getID()); _e.setID(_url.getPath()); }
                     */
                }
                @SuppressWarnings("unchecked")
                NamingEnumeration<Attribute> ne = (NamingEnumeration<Attribute>) sr.getAttributes().getAll();
                while (ne.hasMore()) {
                    Attribute att = ne.next();
                    Object[] attrs = new Object[att.size()];
                    @SuppressWarnings("unchecked")
                    NamingEnumeration<Object> nea = (NamingEnumeration<Object>) att.getAll();
                    for (int i = 0; nea.hasMore(); i++) {
                        attrs[i] = nea.next();
                    }
                    _e.setAttribute(att.getID(), attrs);
                }
                results.add(_e);
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "search() null pointer");
            throw new LDAPException("search null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "search() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
        return results;
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions. Returns a
     * <code>java.util.List<String></code> with the Distinguished names of the entries that match
     * 
     * @param q
     *            DirectoryQuery
     * @return List<String>
     * @exception LDAPException
     */
    public List<String> searchDN(final LDAPDirectoryQuery q) throws LDAPException {
        List<String> results = new ArrayList<String>();
        try {
            DirContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }
            SearchControls ctls = new SearchControls();
            if (connection.hasCountLimit()) {
                ctls.setCountLimit(connection.getCountLimit());
            }
            ctls.setSearchScope(connection.getScope());

            String filter = getQueryString(ctx, q);
            NamingEnumeration<SearchResult> answer = ctx.search(baseDN, filter, ctls);
            while (answer.hasMoreElements()) {
                SearchResult sr = answer.nextElement();
                results.add(sr.getNameInNamespace());
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "searchDN() null pointer");
            throw new LDAPException("search DN null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "searchDN() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
        return results;
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions. Returns a
     * <code>java.util.List<String></code> with the Distinguished names of the entries that match.
     * You can specify a match limit
     * 
     * @param q
     *            DirectoryQuery
     * @param limit
     *            An <code>Integer</code> with the limit of matches
     * @return List<String>
     * @exception LDAPException
     */
    public List<String> searchDN(final LDAPDirectoryQuery q, final Integer limit) throws LDAPException {
        List<String> results = new ArrayList<String>();
        try {
            DirContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("directory service not available");
            }
            SearchControls ctls = new SearchControls();
            if (connection.hasCountLimit()) {
                ctls.setCountLimit(connection.getCountLimit());
            }
            if (limit != null) {
                ctls.setCountLimit(limit.intValue());
            }
            ctls.setSearchScope(connection.getScope());

            String filter = getQueryString(ctx, q);
            NamingEnumeration<SearchResult> answer = ctx.search(baseDN, filter, ctls);
            while (answer.hasMoreElements()) {
                SearchResult sr = answer.nextElement();
                results.add(sr.getNameInNamespace());
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "searchDN() null pointer");
            throw new LDAPException("search DN null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "searchDN() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
        return results;
    }

    /**
     * Search for entry that matches the specific <code>DirectoryQuery</code> conditions. Results
     * will be order using the values of a specific attribute
     * 
     * @param q
     *            DirectoryQuery
     * @param attribute
     *            Name of the attribute that determines the order
     * @return java.util.List<DirectoryEntry>
     * @exception LDAPException
     */
    public List<Identity> sortedSearch(final LDAPDirectoryQuery q, final String attribute) throws LDAPException {
        TreeMap<String, Identity> results = new TreeMap<String, Identity>(Collator.getInstance(new Locale("es")));
        try {
            LdapContext ctx = connection.connect();
            if (ctx == null) {
                throw new LDAPException("Directory service not available");
            }
            SearchControls ctls = new SearchControls();
            if (connection.hasCountLimit()) {
                ctls.setCountLimit(connection.getCountLimit());
            }
            ctls.setSearchScope(connection.getScope());
            ctx.setRequestControls(new Control[] { new SortControl(attribute, Control.NONCRITICAL) });

            String filter = getQueryString(ctx, q);
            NamingEnumeration<SearchResult> answer = ctx.search(baseDN, filter, ctls);
            while (answer.hasMoreElements()) {
                SearchResult sr = answer.nextElement();
                LDAPDirectoryEntry _e = new LDAPDirectoryEntry(sr.getNameInNamespace());
                @SuppressWarnings("unchecked")
                NamingEnumeration<Attribute> ne = (NamingEnumeration<Attribute>) sr.getAttributes().getAll();
                while (ne.hasMore()) {
                    Attribute att = ne.next();
                    Object[] attrs = new Object[att.size()];
                    @SuppressWarnings("unchecked")
                    NamingEnumeration<Object> nea = (NamingEnumeration<Object>) att.getAll();
                    for (int i = 0; nea.hasMore(); i++) {
                        attrs[i] = nea.next();
                    }
                    _e.setAttribute(att.getID(), attrs);
                }
                String _value = String.valueOf(_e.getAttribute(attribute)[0]);
                while (results.containsKey(_value)) {
                    _value = _value.concat("0");
                }
                results.put(_value, _e);
            }
        } catch (NullPointerException e) {
            _log.log(java.util.logging.Level.ALL, "sortedSearch() null pointer");
            throw new LDAPException("sorted search null pointer");
        } catch (NamingException e) {
            _log.log(java.util.logging.Level.ALL, "sortedSearch() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } catch (IOException e) {
            _log.log(java.util.logging.Level.ALL, "sortedSearch() - " + e.getMessage());
            throw new LDAPException(e.getMessage());
        } finally {
            connection.disconnect();
        }
        return new ArrayList<Identity>(results.values());
    }
}
