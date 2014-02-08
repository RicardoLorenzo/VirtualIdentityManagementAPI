package com.ricardolorenzo.identity.user.impl;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.StringTokenizer;

import com.ricardolorenzo.db.DBConnection;
import com.ricardolorenzo.db.DBConnectionManager;
import com.ricardolorenzo.db.DBException;
import com.ricardolorenzo.identity.IdentityException;
import com.ricardolorenzo.identity.script.ScriptCollection;
import com.ricardolorenzo.identity.user.UserIdentity;
import com.ricardolorenzo.identity.user.UserIdentityManager;

public class UserIdentityManagerDatabase extends UserIdentityManager {
    private final static int MODIFICATION_TYPE_ANY = 0;
    private final static int MODIFICATION_TYPE_ADD = 1;
    private final static int MODIFICATION_TYPE_UPDATE = 2;

    private DBConnection dbconnection;

    public UserIdentityManagerDatabase(Properties conf) throws DBException {
        super();
        DBConnectionManager dbm = new DBConnectionManager(conf);
        this.dbconnection = dbm.getConnection();
    }

    private String createQueryFromScript(String content, Map<String, Object[]> attributes)
            throws NoSuchAlgorithmException, DBException, IdentityException {
        if (content == null || content.isEmpty()) {
            throw new IdentityException("invalid script content");
        }
        int _old_offset = 0, index = 0;
        StringBuilder sb = new StringBuilder();
        for (int offset = content.indexOf("[[[", 0); offset != -1; offset = content.indexOf("[[[", offset)) {
            sb.append(content.substring(_old_offset, offset));
            offset += 3;
            if (content.indexOf("]]]", offset) != -1) {
                String attributeName = content.substring(offset, content.indexOf("]]]", offset));
                if (attributes != null && attributes.containsKey(attributeName)) {
                    sb.append("?");
                    if (UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD.equalsIgnoreCase(attributeName)) {
                        this.dbconnection.setObject(index,
                                getEncriptedPassword(getFirstStringValue(attributes.get(attributeName)), false));
                    } else if (ScriptCollection.FIELD_LAST_MODIFIED.equalsIgnoreCase(attributeName)) {
                        /**
                         * Internal case to get modified entries
                         */
                        Object[] values = attributes.get(attributeName);
                        if (values != null && values.length > 0) {
                            if (Calendar.class.isAssignableFrom(attributes.get(attributeName)[0].getClass())) {
                                throw new IdentityException("invalid value for field "
                                        + ScriptCollection.FIELD_LAST_MODIFIED);
                            }
                            this.dbconnection.setObject(index, Calendar.class.cast(attributes.get(attributeName)[0]));
                        } else {
                            this.dbconnection.setObject(index, null);
                        }
                    } else if (UserIdentity.DEFAULT_ATTRIBUTE_LASTMODIFED.equalsIgnoreCase(attributeName)) {
                        Object[] values = attributes.get(attributeName);
                        if (values != null && values.length > 0) {
                            this.dbconnection.setObject(index,
                                    UserIdentity.parseLastModifiedString(String.valueOf(values[0])));
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
    public void addUserIdentity(UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ADD, user);
    }

    @Override
    public void deleteUserIdentity(UserIdentity user) throws IdentityException {
        UserIdentity destinationUser = getUserIdentity(user.getID());
        if (destinationUser == null) {
            throw new IdentityException("user identity does not exists");
        }
        runQueryScript(ScriptCollection.USER_DELETE, destinationUser.getAttributes());
    }

    private List<Map<String, Object>> runQueryScript(final String scriptType, Map<String, Object[]> attributes)
            throws IdentityException {
        List<Map<String, Object>> result = null;
        try {
            this.dbconnection.transactionInit();
            ScriptCollection sc = getScriptCollection();
            if (sc.hasScript(scriptType)) {
                String scriptContent = sc.getScript(scriptType);
                StringTokenizer queries = new StringTokenizer(scriptContent, ";");
                while (queries.hasMoreElements()) {
                    String query = queries.nextToken();
                    if (query != null && !query.isEmpty() && !query.trim().isEmpty()) {
                        createQueryFromScript(query, attributes);
                        List<Map<String, Object>> last_result = this.dbconnection.transactionQuery(query);
                        if (!last_result.isEmpty()) {

                        }
                    }
                }
            }
            this.dbconnection.transactionCommit();
        } catch (DBException e) {
            try {
                this.dbconnection.transactionRollback();
            } catch (DBException e2) {
                // nothing
            }
            throw new IdentityException("database error - " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            try {
                this.dbconnection.transactionRollback();
            } catch (DBException e2) {
                // nothing
            }
            throw new IdentityException(e.getMessage());
        } finally {
            try {
                this.dbconnection.transactionClose();
            } catch (DBException e) {
                // nothing
            }
        }
        return result;
    }

    private String getFirstStringValue(Object[] values) {
        if (values == null) {
            return null;
        }
        for (Object o : values) {
            return String.valueOf(o);
        }
        return null;
    }

    @Override
    public List<UserIdentity> getModifiedUserIdentities(Calendar date) throws IdentityException {
        List<UserIdentity> modifiedIdentities = new ArrayList<UserIdentity>();
        Map<String, Object[]> attributes = new HashMap<String, Object[]>();
        attributes.put(ScriptCollection.FIELD_LAST_MODIFIED, new Object[] { date });
        List<Map<String, Object>> results = runQueryScript(ScriptCollection.USER_SEARCH, attributes);
        if (results.isEmpty()) {
            return null;
        }
        for (Map<String, Object> data : results) {
            modifiedIdentities.add(getUserIdentity(data));
        }
        return modifiedIdentities;
    }

    @Override
    public UserIdentity getUserIdentity(String user) throws IdentityException {
        UserIdentity sourceUser = new UserIdentity();
        UserIdentity destinationUser = new UserIdentity();
        sourceUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_UID, user);
        loadWriteAttributesFromMap(sourceUser, destinationUser);
        List<Map<String, Object>> results = runQueryScript(ScriptCollection.USER_READ, destinationUser.getAttributes());
        if (results.isEmpty()) {
            return null;
        }
        sourceUser.setAttributes(getUserIdentity(results.get(0)));
        return sourceUser;
    }

    private UserIdentity getUserIdentity(Map<String, Object> data) throws IdentityException {
        UserIdentity sourceUser = new UserIdentity();
        UserIdentity destinationUser = new UserIdentity();
        for (Entry<String, Object> e : data.entrySet()) {
            sourceUser.setAttribute(e.getKey(), e.getValue());
        }
        loadReadAttributesFromMap(sourceUser, destinationUser);
        return destinationUser;
    }

    @Override
    public List<UserIdentity> searchUserIdentity(String match) throws IdentityException {
        List<UserIdentity> findedIdentities = new ArrayList<UserIdentity>();
        Map<String, Object[]> attributes = new HashMap<String, Object[]>();
        attributes.put(ScriptCollection.FIELD_MATCH, new Object[] { match });
        List<Map<String, Object>> results = runQueryScript(ScriptCollection.USER_SEARCH, attributes);
        if (results.isEmpty()) {
            return null;
        }
        for (Map<String, Object> data : results) {
            findedIdentities.add(getUserIdentity(data));
        }
        return findedIdentities;
    }

    @Override
    public void updateUserIdentity(UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ANY, user);
    }

    private void storeUserIdentity(final int type, UserIdentity user) throws IdentityException {
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
}
