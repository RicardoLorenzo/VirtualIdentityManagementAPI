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

import com.mongodb.*;
import com.mongodb.util.JSON;
import com.ricardolorenzo.identity.Identity;
import com.ricardolorenzo.identity.IdentityException;
import com.ricardolorenzo.identity.script.ScriptCollection;
import com.ricardolorenzo.identity.user.UserIdentity;
import com.ricardolorenzo.identity.user.UserIdentityManager;
import com.ricardolorenzo.util.ISODate;

import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 *
 * @author Ricardo Lorenzo
 *
 */
public class UserIdentityManagerMongoDB extends UserIdentityManager {
    private final static String DEFAULT_DATABASE = "test";
    private final static int MODIFICATION_TYPE_ANY = 0;
    private final static int MODIFICATION_TYPE_ADD = 1;
    private final static int MODIFICATION_TYPE_UPDATE = 2;
    private final static List<String> OPERATIONS = new ArrayList<String>();

    static {
        OPERATIONS.add("insert");
        OPERATIONS.add("update");
        OPERATIONS.add("find");
        OPERATIONS.add("aggregate");
        OPERATIONS.add("delete");
    }

    private final Properties properties;
    private MongoClient mongoClient;
    private boolean databaseUsers = false;
    private BulkWriteOperation operation = null;
    private boolean bulkOperation = false;

    public UserIdentityManagerMongoDB(final Properties conf) throws UnknownHostException {
        this.properties = conf;

        this.databaseUsers = new Boolean(this.properties.getProperty("mongodb.databaseUsers", "true"));

        WriteConcern writeConcern = WriteConcern.MAJORITY;
        String writeConcernType = conf.getProperty("mongodb.writeConcern", "majority").toLowerCase();
        if ("majority".equals(writeConcernType)) {
            writeConcern = WriteConcern.UNACKNOWLEDGED;
        } else if ("unacknowledged".equals(writeConcernType)) {
            writeConcern = WriteConcern.UNACKNOWLEDGED;
        } else if ("acknowledged".equals(writeConcernType)) {
            writeConcern = WriteConcern.ACKNOWLEDGED;
        } else if ("journaled".equals(writeConcernType)) {
            writeConcern = WriteConcern.JOURNALED;
        } else if ("replica_acknowledged".equals(writeConcernType)) {
            writeConcern = WriteConcern.REPLICA_ACKNOWLEDGED;
        }

        ReadPreference readPreference = null;
        String readPreferenceType = conf.getProperty("mongodb.readPreference", "primary").toLowerCase();
        if ("primary".equals(readPreferenceType)) {
            readPreference = ReadPreference.primary();
        } else if ("primary_preferred".equals(readPreferenceType)) {
            readPreference = ReadPreference.primaryPreferred();
        } else if ("secondary".equals(readPreferenceType)) {
            readPreference = ReadPreference.secondary();
        } else if ("secondary_preferred".equals(readPreferenceType)) {
            readPreference = ReadPreference.secondaryPreferred();
        } else if ("nearest".equals(readPreferenceType)) {
            readPreference = ReadPreference.nearest();
        }

        MongoClientOptions.Builder options = MongoClientOptions.builder();
        options.writeConcern(writeConcern);
        options.readPreference(readPreference);
        try {
            options.connectionsPerHost(Integer.parseInt(conf.getProperty("mongodb.threads", "100")));
        } catch(NumberFormatException e) {
            options.connectionsPerHost(100);
        }

        MongoClientURI mongoClientURI = new MongoClientURI(conf.getProperty("mongodb.url",
                "mongodb://localhost:27017"), options);
        if(!this.properties.containsKey("mongodb.database")) {
            if(mongoClientURI.getDatabase() != null && !mongoClientURI.getDatabase().isEmpty()) {
                this.properties.setProperty("mongodb.database", mongoClientURI.getDatabase());
            } else {
                this.properties.setProperty("mongodb.database", DEFAULT_DATABASE);
            }
        }
        mongoClient = new MongoClient(mongoClientURI);
    }

    @Override
    public void addUserIdentity(final UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ADD, user);
    }

    private String createQueryFromScript(final String content, final Map<String, Object[]> attributes)
            throws NoSuchAlgorithmException, IdentityException {
        if ((content == null) || content.isEmpty()) {
            throw new IdentityException("invalid script content");
        }
        int oldOffset = 0, index = 0;
        final StringBuilder sb = new StringBuilder();
        for (int offset = content.indexOf("[[[", 0); offset != -1; offset = content.indexOf("[[[", offset)) {
            sb.append(content.substring(oldOffset, offset));
            offset += 3;
            if (content.indexOf("]]]", offset) != -1) {
                final String attributeName = content.substring(offset, content.indexOf("]]]", offset));
                if ((attributes != null) && attributes.containsKey(attributeName)) {
                    if (UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD.equalsIgnoreCase(attributeName)) {
                        sb.append(getEncriptedPassword(getFirstStringValue(attributes.get(attributeName)), false));
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
                            Calendar date = Calendar.class.cast(attributes.get(attributeName)[0]);
                            sb.append("{ $gte: ISODate(\"");
                            sb.append(ISODate.toString(date));
                            sb.append("\") }");
                        } else {
                            // an empty value
                            sb.append(" ");
                        }
                    } else if (UserIdentity.DEFAULT_ATTRIBUTE_LASTMODIFED.equalsIgnoreCase(attributeName)) {
                        final Object[] values = attributes.get(attributeName);
                        if ((values != null) && (values.length > 0)) {
                            sb.append(Identity.parseLastModifiedString(String.valueOf(values[0])));
                        } else {
                            // an empty value
                            sb.append(" ");
                        }
                    } else {
                        sb.append(getFirstStringValue(attributes.get(attributeName)));
                    }
                } else {
                    // an empty value
                    sb.append(" ");
                }
                oldOffset = content.indexOf("]]]", offset) + 3;
                index++;
            }
        }
        sb.append(content.substring(oldOffset, content.length()));
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

        if(this.databaseUsers) {
            /**
             * TODO list all users
             */
        } else {
            final List<DBObject> results = runQueryScript(ScriptCollection.USER_SEARCH, attributes);
            if (results.isEmpty()) {
                return null;
            }
            for (final DBObject data : results) {
                modifiedIdentities.add(getUserIdentity(data));
            }
        }
        return modifiedIdentities;
    }

    private static void getUserIdentityAttributes(final DBObject data, String field, UserIdentity user) {
        if(field.contains(".")) {
            DBObject dbObject = DBObject.class.cast(data.get(field));
            String subField = field.substring(0, field.indexOf("."));
            getUserIdentityAttributes(dbObject, subField, user);
        } else {
            user.setAttribute(field, data.get(field));
        }
    }

    private UserIdentity getUserIdentity(final DBObject data) throws IdentityException {
        final UserIdentity sourceUser = new UserIdentity();
        final UserIdentity destinationUser = new UserIdentity();
        for (final String field : data.keySet()) {
            getUserIdentityAttributes(data, field, sourceUser);
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
        final List<DBObject> results = runQueryScript(ScriptCollection.USER_READ,
                destinationUser.getAttributes());
        if (results.isEmpty()) {
            return null;
        }
        sourceUser.setAttributes(getUserIdentity(results.get(0)));
        return sourceUser;
    }

    /**
     * All the scripts should have the following format:
     *
     * {
     *    database.collection: {
     *        operation: insert|update|find|aggregate|delete
     *        query: {}
     *    }
     * }
     *
     * For update operations, you should specify the following:
     *
     * query: {
     *     find: {}
     *     update: {}
     * }
     */
    private List<DBObject> runQueryScript(final String scriptType,
                                                     final Map<String, Object[]> attributes) throws IdentityException {
        List<DBObject> results = new ArrayList<>();
        try {
            DB database = mongoClient.getDB(this.properties.getProperty("mongodb.database"));
            final ScriptCollection sc = getScriptCollection();
            if (sc.hasScript(scriptType)) {
                final String scriptContent = sc.getScript(scriptType);
                String query = createQueryFromScript(scriptContent, attributes);
                DBObject collectionOperation = DBObject.class.cast(JSON.parse(query));

                for(String collection : collectionOperation.keySet()) {
                    if(!database.collectionExists(collection)) {
                        throw new IdentityException("collection [" + collection + "] does not exists");
                    }

                    DBObject dbObject = DBObject.class.cast(collectionOperation.get(collection));
                    if(!dbObject.containsField("operation")) {
                        throw new IdentityException("operation field not specified");
                    }

                    String dbOperation = String.class.cast(dbObject.get("operation")).toLowerCase();
                    if(!OPERATIONS.contains(dbOperation)) {
                        throw new IdentityException("operation [" + dbOperation + "] not supported");
                    }

                    DBObject dbQuery = DBObject.class.cast(dbObject.get("query"));
                    if(dbQuery == null) {
                        throw new IdentityException("query field not specified");
                    }

                    DBCollection coll = database.getCollection(collection);
                    switch(dbOperation) {
                        case "insert": {
                            coll.insert(dbQuery);
                        }
                        case "update": {
                            if(!dbObject.containsField("find")) {
                                throw new IdentityException("find field not found inside the update operation");
                            }
                            if(!dbObject.containsField("update")) {
                                throw new IdentityException("update field not found inside the update operation");
                            }
                            DBObject dbUpdateFind = DBObject.class.cast(dbQuery.get("find"));
                            DBObject dbUpdateFields = DBObject.class.cast(dbQuery.get("update"));
                            coll.update(dbUpdateFind, dbUpdateFields, false, false);
                        }
                        case "delete": {
                            coll.remove(dbQuery);
                        }
                        case "find": {
                            DBCursor cursor = coll.find(dbQuery);
                            while(cursor.hasNext()) {
                                results.add(cursor.next());
                            }
                        }
                        case "aggregate": {
                            List<DBObject> aggregate = new ArrayList<DBObject>();
                            aggregate.add(dbQuery);
                            for(DBObject o : coll.aggregate(aggregate).results()) {
                                results.add(o);
                            }
                        }
                    }
                }
                return results;
            }
        } catch (final NoSuchAlgorithmException e) {
            throw new IdentityException(e.getMessage());
        } finally {
            /**
             * TODO close cursors
             */
        }
        return null;
    }

    @Override
    public List<UserIdentity> searchUserIdentity(final String match) throws IdentityException {
        final List<UserIdentity> users = new ArrayList<UserIdentity>();
        if (match == null) {
            return users;
        }

        final List<UserIdentity> identitiesFound = new ArrayList<UserIdentity>();
        if(this.databaseUsers) {
            /**
             * TODO List the user
             */
        } else {
            final Map<String, Object[]> attributes = new HashMap<String, Object[]>();
            attributes.put(ScriptCollection.FIELD_MATCH, new Object[] { match });
            final List<DBObject> results = runQueryScript(ScriptCollection.USER_SEARCH, attributes);
            if (results.isEmpty()) {
                return null;
            }
            for (final DBObject userData : results) {
                identitiesFound.add(getUserIdentity(userData));
            }
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
            if(this.databaseUsers) {
                DB database = mongoClient.getDB(this.properties.getProperty("mongodb.database"));
                /*
                TODO manage roles
                 */
                String[] roles = { "readWrite" };
                BasicDBObject commandArguments = new BasicDBObject();
                commandArguments.put("user", user.getAttributeFirstValue(UserIdentity.DEFAULT_ATTRIBUTE_UID));
                commandArguments.put("pwd", user.getAttributeFirstValue(UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD));
                commandArguments.put("roles", roles);
                BasicDBObject command = new BasicDBObject("updateUser", commandArguments);
                database.command(command);
            } else {
                runQueryScript(ScriptCollection.USER_ADD, destinationUser.getAttributes());
            }
        } else {
            if (type == MODIFICATION_TYPE_ADD) {
                throw new IdentityException("user identity already exists");
            }
            if(this.databaseUsers) {
                DB database = mongoClient.getDB(this.properties.getProperty("mongodb.database"));
                /*
                TODO manage roles
                 */
                String[] roles = { "readWrite" };
                BasicDBObject commandArguments = new BasicDBObject();
                commandArguments.put("user", user.getAttributeFirstValue(UserIdentity.DEFAULT_ATTRIBUTE_UID));
                commandArguments.put("pwd", user.getAttributeFirstValue(UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD));
                commandArguments.put("roles", roles);
                BasicDBObject command = new BasicDBObject("createUser", commandArguments);
                database.command(command);
            } else {
                runQueryScript(ScriptCollection.USER_UPDATE, destinationUser.getAttributes());
            }
        }
    }

    @Override
    public void updateUserIdentity(final UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ANY, user);
    }
}
