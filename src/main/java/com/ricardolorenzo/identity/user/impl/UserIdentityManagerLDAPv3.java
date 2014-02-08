package com.ricardolorenzo.identity.user.impl;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;

import com.ricardolorenzo.directory.DirectoryException;
import com.ricardolorenzo.directory.DirectoryIdentityManager;
import com.ricardolorenzo.directory.ldap.LDAPConnection;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryEntry;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryQuery;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryWriter;
import com.ricardolorenzo.identity.Identity;
import com.ricardolorenzo.identity.IdentityException;
import com.ricardolorenzo.identity.user.UserIdentity;
import com.ricardolorenzo.identity.user.UserIdentityManager;

public class UserIdentityManagerLDAPv3 extends UserIdentityManager {
    private final static int MODIFICATION_TYPE_ANY = 0;
    private final static int MODIFICATION_TYPE_ADD = 1;
    private final static int MODIFICATION_TYPE_UPDATE = 2;

    private static final String getOrganizationalUnitName(final String DN) {
        String name = "";
        if ((DN == null) || DN.isEmpty()) {
            return name;
        }
        name = DN;
        if (name.contains(",")) {
            name = name.substring(0, name.indexOf(","));
        }
        if (name.contains("=")) {
            name = name.substring(name.indexOf("=") + 1);
        }
        return name;
    }

    private final DirectoryIdentityManager directoryManager;
    private final Properties properties;
    private String basedn;
    private String timezone;
    private String defaultDomain;
    private String defaultUserBranch;
    private String userAccountAttribute;
    private String userCommonNameAttribute;
    private String memberAttribute;

    private final List<String> userObjectclasses;

    public UserIdentityManagerLDAPv3(final Properties conf) throws DirectoryException {
        this.properties = conf;
        this.directoryManager = new DirectoryIdentityManager(conf);
        if (this.properties.containsKey("directory.basedn")) {
            this.basedn = conf.getProperty("directory.basedn");
        }
        if (this.properties.containsKey("directory.timezone")) {
            this.timezone = conf.getProperty("directory.timezone");
        }
        if (this.properties.containsKey("directory.defaults.domain")) {
            this.defaultDomain = this.properties.getProperty("directory.defaults.domain");
        } else {
            this.defaultDomain = "localdomain";
        }
        if (this.properties.containsKey("directory.user.default_branch")) {
            this.defaultUserBranch = this.properties.getProperty("directory.user.default_branch");
        }
        if (this.properties.containsKey("directory.user.account_attribute")) {
            this.userAccountAttribute = this.properties.getProperty("directory.user.account_attribute");
        } else {
            this.userAccountAttribute = "uid";
        }
        if (this.properties.containsKey("directory.user.cn_attribute")) {
            this.userCommonNameAttribute = this.properties.getProperty("directory.user.cn_attribute");
        } else {
            this.userCommonNameAttribute = "cn";
        }
        if (this.properties.containsKey("directory.group.member")) {
            this.memberAttribute = this.properties.getProperty("directory.group.member");
        } else {
            this.memberAttribute = "member";
        }
        this.userObjectclasses = new ArrayList<String>();
        if (this.properties.containsKey("directory.user.objectclasses")) {
            this.userObjectclasses.addAll(getList(this.properties.getProperty("directory.user.objectclasses")));
        }
    }

    @Override
    public void addUserIdentity(final UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ADD, user);
    }

    private void createBranch(final String branch) throws DirectoryException {
        final String name = getOrganizationalUnitName(branch);
        final Identity i = new LDAPDirectoryEntry(branch);
        i.setAttribute("objectClass", new String[] { "top", "organizationalUnit" });
        i.setAttribute("ou", name);
        this.directoryManager.addIdentity(i);
    }

    @Override
    public void deleteUserIdentity(final UserIdentity user) throws IdentityException {
        try {
            String distinguishedName = null;
            if (user.hasAttribute("dn")) {
                distinguishedName = user.getAttributeFirstStringValue("dn");
            } else {
                final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
                try {
                    this.directoryManager.setScope(LDAPConnection.SUBTREE_SCOPE);
                    for (final String objectClass : this.userObjectclasses) {
                        q.addCondition("objectclass", objectClass, LDAPDirectoryQuery.EXACT);
                    }
                    q.addCondition(this.userAccountAttribute,
                            user.getAttributeFirstValue(UserIdentity.DEFAULT_ATTRIBUTE_UID), LDAPDirectoryQuery.EXACT);
                    final List<Identity> result = this.directoryManager.searchIdentities(q);
                    if ((result == null) || result.isEmpty()) {
                        throw new IdentityException("user not found on directory");
                    }
                    distinguishedName = result.get(0).getID();
                } catch (final DirectoryException e) {
                    /**
                     * TODO Detailed log
                     */
                    logError(e);
                    throw new IdentityException(e);
                }
            }
            this.directoryManager.removeIdentity(distinguishedName);
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e);
        }
    }

    private Calendar getCalendarAttribute(final String value) throws IdentityException {
        if ((value == null) || !value.matches("[0-9.Z]+")) {
            throw new IdentityException("invalid attribute date format");
        }
        final Calendar date = Calendar.getInstance();
        if (value.endsWith("Z")) {
            date.setTimeZone(TimeZone.getTimeZone("UTC"));
        } else if (this.timezone != null) {
            date.setTimeZone(TimeZone.getTimeZone(this.timezone));
        }
        date.set(Calendar.YEAR, Integer.parseInt(value.substring(0, 4)));
        date.set(Calendar.MONTH, Integer.parseInt(value.substring(4, 6)) - 1);
        date.set(Calendar.DAY_OF_MONTH, Integer.parseInt(value.substring(6, 8)));
        date.set(Calendar.HOUR_OF_DAY, Integer.parseInt(value.substring(8, 10)));
        date.set(Calendar.MINUTE, Integer.parseInt(value.substring(10, 12)));
        if (value.length() > 13) {
            date.set(Calendar.SECOND, Integer.parseInt(value.substring(12, 14)));
        } else {
            date.set(Calendar.SECOND, 0);
        }
        date.set(Calendar.MILLISECOND, 0);
        return date;
    }

    @Override
    public List<UserIdentity> getModifiedUserIdentities(final Calendar date) throws IdentityException {
        final List<UserIdentity> modifiedUsers = new ArrayList<UserIdentity>();
        try {
            this.directoryManager.setScope(LDAPConnection.ONE_SCOPE);
            LDAPDirectoryQuery q = new LDAPDirectoryQuery();
            q.addCondition("objectclass", "top", LDAPDirectoryQuery.EXACT);
            final List<Identity> rootContainers = this.directoryManager.searchIdentities(q);
            for (final Identity i : rootContainers) {
                this.directoryManager.setScope(LDAPConnection.SUBTREE_SCOPE);
                q = new LDAPDirectoryQuery();
                for (final String objectClass : this.userObjectclasses) {
                    q.addCondition("objectclass", objectClass, LDAPDirectoryQuery.EXACT);
                }
                if (i.hasAttribute("ou")) {
                    q.addCondition("ou", i.getAttributeFirstStringValue("ou"), LDAPDirectoryQuery.BRANCH);
                } else if (i.hasAttribute("cn")) {
                    q.addCondition("cn", i.getAttributeFirstStringValue("ou"), LDAPDirectoryQuery.BRANCH);
                }
                if (i.hasAttribute("objectclass") && (i.getAttribute("objectclass") != null)) {
                    final List<Object> wordList = Arrays.asList(i.getAttribute("objectclass"));
                    if (!(wordList.contains("organizationalUnit") || wordList.contains("container"))) {
                        continue;
                    }
                }

                final List<Identity> users = this.directoryManager.searchIdentities(q);
                for (final Identity user : users) {
                    if (!user.hasAttribute(this.userAccountAttribute)) {
                        continue;
                    }

                    if (user.hasAttribute("modifyTimestamp")) {
                        final Calendar srcDate = getCalendarAttribute(String.valueOf(user
                                .getAttribute("modifyTimestamp")[0]));
                        if (date.after(srcDate)) {
                            continue;
                        }
                    } else {
                        try {
                            final List<Object> values = this.directoryManager.getIdentityAttribute(user.getID(),
                                    "modifyTimestamp");
                            if ((values != null) && !values.isEmpty()) {
                                final Calendar srcDate = getCalendarAttribute(String.valueOf(values.get(0)));
                                if (date.after(srcDate)) {
                                    continue;
                                }
                            }
                        } catch (final DirectoryException e) {
                            logError(e);
                        }
                    }

                    modifiedUsers.add(getUserIdentity(user));
                }
            }
        } catch (final Exception e) {
            throw new IdentityException(e);
        }
        return modifiedUsers;
    }

    private UserIdentity getUserIdentity(final Identity user) throws IdentityException {
        final UserIdentity sourceUser = new UserIdentity(user);
        final UserIdentity destinationUser = new UserIdentity(new LDAPDirectoryEntry(sourceUser.getID()));
        destinationUser.setAttribute("dn", sourceUser.getID());

        /**
         * Load attributes from custom map
         */
        loadReadAttributesFromMap(sourceUser, destinationUser);
        destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_LASTMODIFED,
                getUserIdentityModifyTimestamp(sourceUser));
        if (!destinationUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL)) {
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL,
                    destinationUser.getAttributeFirstStringValue(UserIdentity.DEFAULT_ATTRIBUTE_ACCOUNT) + "@"
                            + defaultDomain);
        }
        return destinationUser;
    }

    @Override
    public UserIdentity getUserIdentity(final String user) throws IdentityException {
        if (user == null) {
            return null;
        }
        final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
        try {
            this.directoryManager.setScope(LDAPConnection.SUBTREE_SCOPE);
            for (final String objectClass : this.userObjectclasses) {
                q.addCondition("objectclass", objectClass, LDAPDirectoryQuery.EXACT);
            }
            q.addCondition(this.userAccountAttribute, user, LDAPDirectoryQuery.EXACT);
            final List<Identity> result = this.directoryManager.searchIdentities(q);
            if ((result != null) && !result.isEmpty()) {
                return getUserIdentity(result.get(0));
            }
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e);
        }
        return null;
    }

    private void loadIdentityAttributes(final Identity destinationIdentity, final UserIdentity sourceUser)
            throws DirectoryException, IdentityException {
        /**
         * Load attributes from custom map
         */
        loadWriteAttributesFromMap(sourceUser, destinationIdentity);
        if (sourceUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD)) {
            final List<String> passwords = new ArrayList<String>();
            for (final Object o : sourceUser.getAttribute(UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD)) {
                final String password = String.valueOf(o);
                try {
                    passwords.add(getEncriptedPassword(password, true));
                } catch (final NoSuchAlgorithmException e) {
                    logError(e);
                }
            }
            if (!passwords.isEmpty()) {
                destinationIdentity.setAttribute("userPassword", passwords.toArray());
            }
        }
    }

    private String getUserIdentityModifyTimestamp(final UserIdentity sourceUser) throws IdentityException {
        if (sourceUser.hasAttribute("modifyTimestamp")) {
            final Calendar lastModified = getCalendarAttribute(String.valueOf(sourceUser
                    .getAttribute("modifyTimestamp")[0]));
            return UserIdentity.getLastModifiedString(lastModified);
        } else {
            try {
                final List<Object> values = this.directoryManager.getIdentityAttribute(sourceUser.getID(),
                        "modifyTimestamp");
                if ((values != null) && !values.isEmpty()) {
                    final Calendar lastModified = getCalendarAttribute(String.valueOf(values.get(0)));
                    return UserIdentity.getLastModifiedString(lastModified);
                }
            } catch (final DirectoryException e) {
                logError(e);
            }
        }
        return null;
    }

    @Override
    public List<UserIdentity> searchUserIdentity(final String match) throws IdentityException {
        final List<UserIdentity> users = new ArrayList<UserIdentity>();
        if (match == null) {
            return users;
        }
        try {
            final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
            this.directoryManager.setScope(LDAPConnection.SUBTREE_SCOPE);
            for (final String objectClass : this.userObjectclasses) {
                q.addCondition("objectclass", objectClass, LDAPDirectoryQuery.EXACT);
            }
            q.addCondition(this.userAccountAttribute, match, LDAPDirectoryQuery.CONTAINS);
            for (final Identity user : this.directoryManager.sortedSearch(q, this.userCommonNameAttribute)) {
                users.add(getUserIdentity(user));
            }
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e);
        }
        return users;
    }

    private void storeNewUserIdentity(final UserIdentity actualUser, final String uid) throws IdentityException {
        try {
            final StringBuilder sb = new StringBuilder();
            sb.append(this.userAccountAttribute);
            sb.append("=");
            sb.append(uid);
            sb.append(",");
            if (this.defaultUserBranch != null) {
                final StringBuilder branch = new StringBuilder();
                branch.append(this.defaultUserBranch);
                branch.append(",");
                branch.append(this.basedn);
                if (!this.directoryManager.checkIdentity(branch.toString())) {
                    createBranch(branch.toString());
                }
                sb.append(this.defaultUserBranch);
            } else {
                final StringBuilder branch = new StringBuilder();
                branch.append("ou=People,");
                branch.append(this.basedn);
                if (!this.directoryManager.checkIdentity(branch.toString())) {
                    createBranch(branch.toString());
                }
                sb.append("ou=People");
            }
            sb.append(",");
            sb.append(this.basedn);
            final Identity i = new LDAPDirectoryEntry(sb.toString());
            actualUser.setAttribute(this.userAccountAttribute, uid);
            loadIdentityAttributes(i, actualUser);
            this.directoryManager.addIdentity(i, LDAPDirectoryWriter.DIRECTORY_TYPE_LDAPV3);
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e);
        }
    }

    private void storeUserIdentity(final int type, final UserIdentity user) throws IdentityException {
        UserIdentity actualUser = getUserIdentity(user.getID());
        final String uid = getReadAttributeFromMap(actualUser, UserIdentity.DEFAULT_ATTRIBUTE_UID);

        if (actualUser == null) {
            if (type == MODIFICATION_TYPE_UPDATE) {
                throw new IdentityException("user identity does not exists");
            }
            actualUser = new UserIdentity();
            storeNewUserIdentity(actualUser, uid);
        } else {
            if (type == MODIFICATION_TYPE_ADD) {
                throw new IdentityException("user identity already exists");
            }

            try {
                final Identity i = this.directoryManager.getIdentity(actualUser.getAttributeFirstStringValue("dn"));
                loadIdentityAttributes(i, actualUser);
                this.directoryManager.updateIdentity(i, LDAPDirectoryWriter.DIRECTORY_TYPE_LDAPV3);
            } catch (final DirectoryException e) {
                logError(e);
                throw new IdentityException(e);
            }
        }
    }

    @Override
    public void updateUserIdentity(final UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ANY, user);
    }
}
