/*
 * UserIdentityManagerDatabase class
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
package com.ricardolorenzo.identity.user.impl;

import com.ricardolorenzo.db.DBConnection;
import com.ricardolorenzo.db.DBConnectionManager;
import com.ricardolorenzo.db.DBException;
import com.ricardolorenzo.identity.Identity;
import com.ricardolorenzo.identity.IdentityException;
import com.ricardolorenzo.identity.script.ScriptCollection;
import com.ricardolorenzo.identity.user.UserIdentity;
import com.ricardolorenzo.identity.user.UserIdentityManager;

import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.Map.Entry;

/**
 * 
 * @author Ricardo Lorenzo
 * 
 */
public class UserIdentityManagerJDBCDatabase extends UserIdentityManager {
    private final static int MODIFICATION_TYPE_ANY = 0;
    private final static int MODIFICATION_TYPE_ADD = 1;
    private final static int MODIFICATION_TYPE_UPDATE = 2;

    private final DBConnection dbconnection;

    public UserIdentityManagerJDBCDatabase(final Properties conf) throws DBException {
        super();
        final DBConnectionManager dbm = new DBConnectionManager(conf);
        this.dbconnection = dbm.getConnection();
    }

    @Override
    public void addUserIdentity(final UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ADD, user);
    }

    private String createQueryFromScript(final String content, final Map<String, Object[]> attributes)
            throws NoSuchAlgorithmException, DBException, IdentityException {
        if ((content == null) || content.isEmpty()) {
            throw new IdentityException("invalid script content");
        }
        int _old_offset = 0, index = 0;
        final StringBuilder sb = new StringBuilder();
        for (int offset = content.indexOf("[[[", 0); offset != -1; offset = content.indexOf("[[[", offset)) {
            sb.append(content.substring(_old_offset, offset));
            offset += 3;
            if (content.indexOf("]]]", offset) != -1) {
                final String attributeName = content.substring(offset, content.indexOf("]]]", offset));
                if ((attributes != null) && attributes.containsKey(attributeName)) {
                    sb.append("?");
                    if (UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD.equalsIgnoreCase(attributeName)) {
                        this.dbconnection.setObject(index,
                                getEncriptedPassword(getFirstStringValue(attributes.get(attributeName)), false));
                    } else if (ScriptCollection.FIELD_LAST_MODIFIED.equalsIgnoreCase(attributeName)) {
                        /**
                         * Internal case to get modified entries
                         */
                        final Object[] values = attributes.get(attributeName);
                        if ((values != null) && (values.length > 0)) {
                            if (Calendar.class.isAssignableFrom(attributes.get(attributeName)[0].getClass())) {
                                throw new IdentityException("invalid value for field "
                                        + ScriptCollection.FIELD_LAST_MODIFIED);
                            }
                            this.dbconnection.setObject(index, Calendar.class.cast(attributes.get(attributeName)[0]));
                        } else {
                            this.dbconnection.setObject(index, null);
                        }
                    } else if (UserIdentity.DEFAULT_ATTRIBUTE_LASTMODIFED.equalsIgnoreCase(attributeName)) {
                        final Object[] values = attributes.get(attributeName);
                        if ((values != null) && (values.length > 0)) {
                            this.dbconnection.setObject(index,
                                    Identity.parseLastModifiedString(String.valueOf(values[0])));
                        } else {
                            this.dbconnection.setObject(index, null);
                        }
                    } else {
                        this.dbconnection.setObject(index, getFirstStringValue(attributes.get(attributeName)));
                    }
                } else {
                    sb.append("?");
                    this.dbconnection.setObject(index, null);
                }
                _old_offset = content.indexOf("]]]", offset) + 3;
                index++;
            }
        }
        sb.append(content.substring(_old_offset, content.length()));
        return sb.toString();
    }

    @Override
    public void deleteUserIdentity(final UserIdentity user) throws IdentityException {
        final UserIdentity destinationUser = getUserIdentity(user.getID());
        if (destinationUser == null) {
            throw new IdentityException("user identity does not exists");
        }
        runQueryScript(ScriptCollection.USER_DELETE, destinationUser.getAttributes());
    }

    private static String getFirstStringValue(final Object[] values) {
        if (values == null) {
            return null;
        }
        for (final Object o : values) {
            return String.valueOf(o);
        }
        return null;
    }

    @Override
    public List<UserIdentity> getModifiedUserIdentities(final Calendar date) throws IdentityException {
        final List<UserIdentity> modifiedIdentities = new ArrayList<UserIdentity>();
        final Map<String, Object[]> attributes = new HashMap<String, Object[]>();
        attributes.put(ScriptCollection.FIELD_LAST_MODIFIED, new Object[] { date });
        final List<Map<String, Object>> results = runQueryScript(ScriptCollection.USER_SEARCH, attributes);
        if (results.isEmpty()) {
            return null;
        }
        for (final Map<String, Object> data : results) {
            modifiedIdentities.add(getUserIdentity(data));
        }
        return modifiedIdentities;
    }

    private UserIdentity getUserIdentity(final Map<String, Object> data) throws IdentityException {
        final UserIdentity sourceUser = new UserIdentity();
        final UserIdentity destinationUser = new UserIdentity();
        for (final Entry<String, Object> e : data.entrySet()) {
            sourceUser.setAttribute(e.getKey(), e.getValue());
        }
        loadReadAttributesFromMap(sourceUser, destinationUser);
        return destinationUser;
    }

    @Override
    public UserIdentity getUserIdentity(final String user) throws IdentityException {
        final UserIdentity sourceUser = new UserIdentity();
        final UserIdentity destinationUser = new UserIdentity();
        sourceUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_UID, user);
        loadWriteAttributesFromMap(sourceUser, destinationUser);
        final List<Map<String, Object>> results = runQueryScript(ScriptCollection.USER_READ,
                destinationUser.getAttributes());
        if (results.isEmpty()) {
            return null;
        }
        sourceUser.setAttributes(getUserIdentity(results.get(0)));
        return sourceUser;
    }

    private List<Map<String, Object>> runQueryScript(final String scriptType, final Map<String, Object[]> attributes)
            throws IdentityException {
        final List<Map<String, Object>> result = null;
        try {
            this.dbconnection.transactionInit();
            final ScriptCollection sc = getScriptCollection();
            if (sc.hasScript(scriptType)) {
                final String scriptContent = sc.getScript(scriptType);
                final StringTokenizer queries = new StringTokenizer(scriptContent, ";");
                while (queries.hasMoreElements()) {
                    String query = queries.nextToken();
                    if ((query != null) && !query.isEmpty() && !query.trim().isEmpty()) {
                        query = createQueryFromScript(query, attributes);
                        final List<Map<String, Object>> last_result = this.dbconnection.transactionQuery(query);
                        if (!last_result.isEmpty()) {
                            result.addAll(last_result);
                        }
                    }
                }
            }
            this.dbconnection.transactionCommit();
        } catch (final DBException e) {
            try {
                this.dbconnection.transactionRollback();
            } catch (final DBException e2) {
                // nothing
            }
            throw new IdentityException("database error - " + e.getMessage());
        } catch (final NoSuchAlgorithmException e) {
            try {
                this.dbconnection.transactionRollback();
            } catch (final DBException e2) {
                // nothing
            }
            throw new IdentityException(e.getMessage());
        } finally {
            try {
                this.dbconnection.transactionClose();
            } catch (final DBException e) {
                // nothing
            }
        }
        return result;
    }

    @Override
    public List<UserIdentity> searchUserIdentity(final String match) throws IdentityException {
        final List<UserIdentity> identitiesFound = new ArrayList<UserIdentity>();
        final Map<String, Object[]> attributes = new HashMap<String, Object[]>();
        attributes.put(ScriptCollection.FIELD_MATCH, new Object[] { match });
        final List<Map<String, Object>> results = runQueryScript(ScriptCollection.USER_SEARCH, attributes);
        if (results.isEmpty()) {
            return null;
        }
        for (final Map<String, Object> data : results) {
            identitiesFound.add(getUserIdentity(data));
        }
        return identitiesFound;
    }

    private void storeUserIdentity(final int type, final UserIdentity user) throws IdentityException {
        UserIdentity destinationUser = getUserIdentity(user.getID());
        if (destinationUser == null) {
            if (type == MODIFICATION_TYPE_UPDATE) {
                throw new IdentityException("user identity does not exists");
            }
            destinationUser = new UserIdentity();
            runQueryScript(ScriptCollection.USER_ADD, destinationUser.getAttributes());
        } else {
            if (type == MODIFICATION_TYPE_ADD) {
                throw new IdentityException("user identity already exists");
            }
            runQueryScript(ScriptCollection.USER_UPDATE, destinationUser.getAttributes());
        }
    }

    @Override
    public void updateUserIdentity(final UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ANY, user);
    }
}
