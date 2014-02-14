/*
 * UserIdentityManagerMSAD class
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
import com.ricardolorenzo.identity.IdentityAttributeMap;
import com.ricardolorenzo.identity.IdentityException;
import com.ricardolorenzo.identity.user.UserIdentity;
import com.ricardolorenzo.identity.user.UserIdentityManager;

/**
 * 
 * @author Ricardo Lorenzo
 * 
 */
public class UserIdentityManagerMSAD extends UserIdentityManager {
    private final static int MODIFICATION_TYPE_ANY = 0;
    private final static int MODIFICATION_TYPE_ADD = 1;
    private final static int MODIFICATION_TYPE_UPDATE = 2;

    private static final String getOrganizationalUnitName(final String DN) {
        String _name = "";
        if ((DN == null) || DN.isEmpty()) {
            return _name;
        }
        _name = DN;
        if (_name.contains(",")) {
            _name = _name.substring(0, _name.indexOf(","));
        }
        if (_name.contains("=")) {
            _name = _name.substring(_name.indexOf("=") + 1);
        }
        return _name;
    }

    private final DirectoryIdentityManager directoryManager;
    private final Properties properties;
    private String basedn;
    private String timezone;
    private String defaultDomain;
    private String defaultUserBranch;
    private boolean USER_NOT_UPDATE_MAIL_ALIASES;
    private boolean USER_PASSWORD_NOT_REQUESTED;
    private boolean USER_PASSWORD_CANNOT_CHANGE;
    private boolean USER_PASSWORD_DO_NOT_EXPIRE;
    private boolean USER_PASSWORD_EXPIRED;
    private boolean USER_PASSWORD_NEW_MUST_CHANGE;
    private boolean USER_ACCOUNT_DISABLE;

    private boolean USER_ACCOUNT_NORMAL;

    public UserIdentityManagerMSAD(final Properties conf) throws DirectoryException {
        super();
        this.properties = conf;
        this.directoryManager = new DirectoryIdentityManager(conf);
        if (this.properties.containsKey("directory.basedn")) {
            this.basedn = this.properties.getProperty("directory.basedn");
        }
        if (this.properties.containsKey("directory.timezone")) {
            this.timezone = this.properties.getProperty("directory.timezone");
        }
        if (this.properties.containsKey("directory.defaults.domain")) {
            this.defaultDomain = this.properties.getProperty("directory.defaults.domain");
        } else {
            this.defaultDomain = "localdomain";
        }
        if (this.properties.containsKey("directory.user.default_branch")) {
            this.defaultUserBranch = this.properties.getProperty("directory.user.default_branch");
        }
        if (this.properties.containsKey("directory.user.not_udpdate_mail_aliases")
                && "true".equalsIgnoreCase(this.properties.getProperty("directory.user.not_udpdate_mail_aliases"))) {
            this.USER_NOT_UPDATE_MAIL_ALIASES = true;
        } else {
            this.USER_NOT_UPDATE_MAIL_ALIASES = false;
        }
        if (this.properties.containsKey("directory.user.password_not_requested")
                && "true".equalsIgnoreCase(this.properties.getProperty("directory.user.password_not_requested"))) {
            this.USER_PASSWORD_NOT_REQUESTED = true;
        } else {
            this.USER_PASSWORD_NOT_REQUESTED = false;
        }
        if (this.properties.containsKey("directory.user.password_cannot_change")
                && "true".equalsIgnoreCase(this.properties.getProperty("directory.user.password_cannot_change"))) {
            this.USER_PASSWORD_CANNOT_CHANGE = true;
        } else {
            this.USER_PASSWORD_CANNOT_CHANGE = false;
        }
        if (this.properties.containsKey("directory.user.password_do_not_expire")
                && "true".equalsIgnoreCase(this.properties.getProperty("directory.user.password_do_not_expire"))) {
            this.USER_PASSWORD_DO_NOT_EXPIRE = true;
        } else {
            this.USER_PASSWORD_DO_NOT_EXPIRE = false;
        }
        if (this.properties.containsKey("directory.user.password_expired")
                && "true".equalsIgnoreCase(this.properties.getProperty("directory.user.password_expired"))) {
            this.USER_PASSWORD_EXPIRED = true;
        } else {
            this.USER_PASSWORD_EXPIRED = false;
        }
        if (this.properties.containsKey("directory.user.account_disable")
                && "true".equalsIgnoreCase(this.properties.getProperty("directory.user.account_disable"))) {
            this.USER_ACCOUNT_DISABLE = true;
        } else {
            this.USER_ACCOUNT_DISABLE = false;
        }
        if (this.properties.containsKey("directory.user.normal_account")
                && "true".equalsIgnoreCase(this.properties.getProperty("directory.user.normal_account"))) {
            this.USER_ACCOUNT_NORMAL = true;
        } else {
            this.USER_ACCOUNT_NORMAL = false;
        }
        if (!this.USER_ACCOUNT_DISABLE && !this.USER_PASSWORD_NOT_REQUESTED && !this.USER_PASSWORD_DO_NOT_EXPIRE
                && !this.USER_PASSWORD_EXPIRED && !this.USER_ACCOUNT_NORMAL) {
            this.USER_ACCOUNT_NORMAL = true;
            this.USER_PASSWORD_DO_NOT_EXPIRE = true;
        }
    }

    @Override
    public void addUserIdentity(final UserIdentity user) throws IdentityException {
        storeUserIdentity(MODIFICATION_TYPE_ADD, user);
    }

    private void createBranch(final StringBuilder _branch) throws DirectoryException {
        final String _name = getOrganizationalUnitName(_branch.toString());
        final Identity i = new LDAPDirectoryEntry(_branch.toString());
        i.setAttribute("objectClass", new String[] { "top", "organizationalUnit" });
        i.setAttribute("distinguishedName", _branch.toString());
        i.setAttribute("instanceType", "4");
        i.setAttribute("objectCategory", "CN=Organizational-Unit,CN=Schema,CN=Configuration," + this.basedn);
        i.setAttribute("ou", _name);
        i.setAttribute("name", _name);
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
                    q.addCondition("objectclass", "person", LDAPDirectoryQuery.EXACT);
                    q.addCondition("sAMAccountName", user.getAttributeFirstValue(UserIdentity.DEFAULT_ATTRIBUTE_UID),
                            LDAPDirectoryQuery.EXACT);
                    final List<Identity> result = this.directoryManager.searchIdentities(q);
                    if ((result == null) || result.isEmpty()) {
                        throw new IdentityException("user not found on directory");
                    }
                    distinguishedName = result.get(0).getID();
                } catch (final DirectoryException e) {
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
                q.addCondition("objectclass", "person", LDAPDirectoryQuery.EXACT);
                q.addCondition("objectclass", "computer", LDAPDirectoryQuery.NOT_EXACT);
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
                    try {
                        if (!user.hasAttribute("sAMAccountName")) {
                            continue;
                        }
                        if ((date != null) && user.hasAttribute("whenChanged")) {
                            final Calendar lastModified = getMSADCalendarAttribute(user
                                    .getAttributeFirstStringValue("whenChanged"));
                            if (date.after(lastModified)) {
                                continue;
                            }
                        }
                        modifiedUsers.add(getUserIdentity(user));
                    } catch (final Exception e) {
                        logError(e);
                    }
                }
            }
        } catch (final Exception e) {
            throw new IdentityException(e);
        }
        return modifiedUsers;
    }

    private Calendar getMSADCalendarAttribute(final String value) throws IdentityException {
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

    public final Identity getUserBasicIdentity(final String userID) throws IdentityException {
        if (userID == null) {
            return null;
        }
        final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
        try {
            this.directoryManager.setScope(LDAPConnection.SUBTREE_SCOPE);
            q.addCondition("objectclass", "person", LDAPDirectoryQuery.EXACT);
            q.addCondition("sAMAccountName", userID, LDAPDirectoryQuery.EXACT);
            final List<Identity> results = this.directoryManager.searchIdentities(q);
            if ((results != null) && !results.isEmpty()) {
                return results.get(0);
            }
        } catch (final DirectoryException e) {
            throw new IdentityException(e);
        }
        return null;
    }

    public final UserIdentity getUserIdentity(final Identity user) throws IdentityException {
        final UserIdentity sourceUser = new UserIdentity(user);
        final UserIdentity destinationUser = new UserIdentity(new LDAPDirectoryEntry(sourceUser.getID()));
        destinationUser.setAttribute("dn", sourceUser.getID());
        loadAttributesFromMap(IdentityAttributeMap.getDefaultReadMap(), sourceUser, destinationUser);
        destinationUser.setAttributes(getUserIdentityAttributeOU(sourceUser));
        destinationUser.setAttributes(getUserIdentityAttributeMail(sourceUser));
        destinationUser.setAttributes(getUserIdentityAttributeManager(sourceUser));

        if (sourceUser.hasAttribute("userAccountControl")) {
            try {
                final long _UAC = Long.parseLong(String.valueOf(sourceUser.getAttribute("userAccountControl")[0]));
                if ((_UAC & LDAPDirectoryWriter.MSAD_UF_ACCOUNTDISABLE) == LDAPDirectoryWriter.MSAD_UF_ACCOUNTDISABLE) {
                    destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_ACCOUNT, "disabled");
                }
            } catch (final NumberFormatException e) {
                // nothing
            }
        }

        if (!destinationUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_DISPLAYNAME)) {
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_DISPLAYNAME, sourceUser.getAttribute("cn"));
        }

        if (!destinationUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_HOMEDRIVE)
                && (this.properties.getProperty("directory.defaults.homeDrive") != null)) {
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_HOMEDRIVE,
                    this.properties.getProperty("directory.defaults.homeDrive"));
        }
        if (!destinationUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_HOMEDIRECTORY)
                && (this.properties.getProperty("directory.defaults.homeServer") != null)) {
            final StringBuilder sb = new StringBuilder();
            sb.append("\\\\");
            sb.append(this.properties.getProperty("directory.defaults.homeServer"));
            sb.append("\\");
            sb.append(sourceUser.getAttributeFirstStringValue("sAMAccountName"));
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_HOMEDIRECTORY, sb.toString());
        }

        /**
         * Load attributes from custom map
         */
        loadReadAttributesFromMap(sourceUser, destinationUser);

        /**
         * Load the modification time
         */
        if (sourceUser.hasAttribute("whenChanged")) {
            final Calendar lastModified = getMSADCalendarAttribute(sourceUser
                    .getAttributeFirstStringValue("whenChanged"));
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_LASTMODIFED,
                    Identity.getLastModifiedString(lastModified));
        }
        return destinationUser;
    }

    @Override
    public UserIdentity getUserIdentity(final String userID) throws IdentityException {
        if (userID == null) {
            return null;
        }
        Identity user = getUserBasicIdentity(userID);
        if (user != null) {
            return getUserIdentity(user);
        }
        return null;
    }

    private UserIdentity getUserIdentityAttributeMail(final UserIdentity sourceUser) {
        final UserIdentity destinationUser = new UserIdentity();
        if (sourceUser.hasAttribute("mail")) {
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAILDROP, sourceUser.getAttribute("mail"));
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL, sourceUser.getAttribute("mail"));
        } else {
            final StringBuilder sb = new StringBuilder();
            sb.append(destinationUser.getAttributeFirstStringValue(UserIdentity.DEFAULT_ATTRIBUTE_UID));
            sb.append("@");
            sb.append(this.defaultDomain);
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAILDROP, sb.toString());
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL, sb.toString());
        }
        if (sourceUser.hasAttribute("proxyAddresses")) {
            final List<String> mailAddresses = new ArrayList<String>();
            if (destinationUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL)) {
                for (final Object _o : destinationUser.getAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL)) {
                    mailAddresses.add(String.valueOf(_o));
                }
            }
            for (final Object _o : sourceUser.getAttribute("proxyAddresses")) {
                String _mail = String.valueOf(_o);
                if (_mail.startsWith("smtp:") || _mail.startsWith("SMTP:")) {
                    _mail = _mail.substring(5);
                    if (!mailAddresses.contains(_mail)) {
                        mailAddresses.add(_mail);
                    }
                }
            }
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL, mailAddresses.toArray());
        }
        return destinationUser;
    }

    private UserIdentity getUserIdentityAttributeManager(final UserIdentity sourceUser) {
        final UserIdentity destinationUser = new UserIdentity();
        if (sourceUser.hasAttribute("manager")) {
            final List<UserIdentity> managers = new ArrayList<UserIdentity>();
            for (final Object manager : sourceUser.getAttribute("manager")) {
                String value = String.valueOf(manager);
                if (value.contains("=") && value.contains(",")) {
                    value = value.substring(value.indexOf("=") + 1, value.indexOf(","));
                    try {
                        final UserIdentity i = getUserIdentity(value);
                        managers.add(i);
                    } catch (final IdentityException e) {
                        logError("user for manager error", e);
                    }
                }
            }
            if (managers.isEmpty()) {
                destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MANAGER, managers.toArray());
            }
        }
        return destinationUser;
    }

    private UserIdentity getUserIdentityAttributeOU(final UserIdentity sourceUser) {
        final UserIdentity destinationUser = new UserIdentity();
        final List<String> values = new ArrayList<String>();
        if (sourceUser.hasAttribute("memberOf")) {
            final Object[] chain_values = sourceUser.getAttribute("memberOf");
            for (int j = chain_values.length; --j >= 0;) {
                String chain = String.valueOf(chain_values[j]);
                if (chain.toLowerCase().indexOf("ou=groups") == -1) {
                    while (chain.toLowerCase().startsWith("ou=") || chain.toLowerCase().startsWith("cn=")) {
                        if (values.indexOf(chain.substring(0, chain.indexOf(",")).substring(chain.indexOf("=") + 1)) == -1) {
                            final String val_tmp = chain.substring(0, chain.indexOf(",")).substring(
                                    chain.indexOf("=") + 1);
                            values.add(val_tmp.toLowerCase());
                        }
                        chain = chain.substring(chain.indexOf(",") + 1).trim();
                    }
                }
            }
        }
        if (values.isEmpty()) {
            destinationUser.setAttribute(UserIdentity.DEFAULT_ATTRIBUTE_OU, values.toArray());
        }

        return destinationUser;
    }

    private void loadIdentityAttributeAccountStatus(final Identity destinationIdentity, final UserIdentity sourceUser) {
        if (sourceUser.hasAttributeValue(UserIdentity.DEFAULT_ATTRIBUTE_ACCOUNT, "disabled")) {
            destinationIdentity.setAttribute(
                    "userAccountControl",
                    Integer.toString(LDAPDirectoryWriter.MSAD_UF_NORMAL_ACCOUNT
                            + LDAPDirectoryWriter.MSAD_UF_PASSWD_NOTREQD + LDAPDirectoryWriter.MSAD_UF_ACCOUNTDISABLE));
        } else {
            Integer _userAccountControl = 0;
            if (this.USER_ACCOUNT_DISABLE || sourceUser.hasAttributeValue("pwdDisabled", "true")) {
                _userAccountControl += LDAPDirectoryWriter.MSAD_UF_ACCOUNTDISABLE;
            }
            if (this.USER_PASSWORD_NOT_REQUESTED) {
                _userAccountControl += LDAPDirectoryWriter.MSAD_UF_PASSWD_NOTREQD;
            }
            if (this.USER_PASSWORD_CANNOT_CHANGE) {
                _userAccountControl += LDAPDirectoryWriter.MSAD_UF_PASSWD_CANT_CHANGE;
            }
            if (this.USER_PASSWORD_DO_NOT_EXPIRE) {
                _userAccountControl += LDAPDirectoryWriter.MSAD_UF_DONT_EXPIRE_PASSWD;
            }
            if (this.USER_PASSWORD_EXPIRED) {
                _userAccountControl += LDAPDirectoryWriter.MSAD_UF_PASSWORD_EXPIRED;
            }
            if (this.USER_ACCOUNT_NORMAL) {
                _userAccountControl += LDAPDirectoryWriter.MSAD_UF_NORMAL_ACCOUNT;
            }
            destinationIdentity.setAttribute("userAccountControl", Integer.toString(_userAccountControl));
            destinationIdentity.setAttribute("lockoutTime", "0");
        }
    }

    private void loadIdentityAttributeMail(final Identity destinationIdentity, final UserIdentity sourceUser) {
        if (sourceUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAILDROP)) {
            destinationIdentity.setAttribute("mail",
                    sourceUser.getAttributeFirstValue(UserIdentity.DEFAULT_ATTRIBUTE_MAILDROP));
        } else if (sourceUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL)) {
            destinationIdentity.setAttribute("mail",
                    sourceUser.getAttributeFirstValue(UserIdentity.DEFAULT_ATTRIBUTE_MAIL));
        }
        if (!this.USER_NOT_UPDATE_MAIL_ALIASES && sourceUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL)) {
            String defaultMail = null;
            final List<String> mailAddresses = new ArrayList<String>();
            if (sourceUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAILDROP)) {
                defaultMail = sourceUser.getAttributeFirstStringValue(UserIdentity.DEFAULT_ATTRIBUTE_MAILDROP);
                final String _mail = "SMTP:".concat(defaultMail);
                mailAddresses.add(_mail);
            }
            for (final Object _o : sourceUser.getAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MAIL)) {
                String _mail = String.valueOf(_o);
                if (!_mail.startsWith("smtp:") && !_mail.startsWith("SMTP:")) {
                    _mail = "smtp:".concat(_mail);
                }
                if (((defaultMail == null) || !"smtp:".concat(defaultMail).equalsIgnoreCase(_mail))) {
                    if (!mailAddresses.contains(_mail)) {
                        mailAddresses.add(_mail);
                    }
                }
            }
            destinationIdentity.setAttribute("proxyAddresses", mailAddresses.toArray());
        }
    }

    private void loadIdentityAttributeManager(final Identity destinationIdentity, final UserIdentity sourceUser) {
        if (sourceUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MANAGER)) {
            final List<String> managers = new ArrayList<String>();
            for (final Object manager : sourceUser.getAttribute(UserIdentity.DEFAULT_ATTRIBUTE_MANAGER)) {
                String value = null;
                if (manager instanceof UserIdentity) {
                    final UserIdentity i = (UserIdentity) manager;
                    value = i.getAttributeFirstStringValue(UserIdentity.DEFAULT_ATTRIBUTE_UID);
                } else if (manager instanceof String) {
                    value = (String) manager;
                }
                if (value != null) {
                    try {
                        final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
                        q.addCondition("objectclass", "person", LDAPDirectoryQuery.EXACT);
                        q.addCondition("sAMAccountName", value, LDAPDirectoryQuery.EXACT);
                        final List<Identity> _result = this.directoryManager.searchIdentities(q);
                        if ((_result != null) && !_result.isEmpty()) {
                            managers.add(_result.get(0).getID());
                        }
                    } catch (final DirectoryException e) {

                    }
                }
            }
            if (managers.isEmpty()) {
                destinationIdentity.removeAttribute("manager");
            } else {
                destinationIdentity.setAttribute("manager", managers.toArray());
            }
        } else {
            destinationIdentity.removeAttribute("manager");
        }
    }

    private void loadIdentityAttributes(final Identity destinationIdentity, final UserIdentity sourceUser)
            throws DirectoryException, IdentityException {
        loadAttributesFromMap(IdentityAttributeMap.getDefaultWriteMap(), sourceUser, destinationIdentity);

        if (!destinationIdentity.hasAttribute("objectclass")) {
            destinationIdentity.setAttribute("objectclass", new String[] { "top", "person", "organizationalperson",
                    "user" });
        }

        loadAttributesFromMap(IdentityAttributeMap.getDefaultWriteMap(), sourceUser, destinationIdentity);

        destinationIdentity.setAttribute("userPrincipalName",
                sourceUser.getAttributeFirstStringValue(UserIdentity.DEFAULT_ATTRIBUTE_UID) + "@" + this.defaultDomain);
        if (!destinationIdentity.hasAttribute("cn")) {
            destinationIdentity.setAttribute("cn",
                    sourceUser.getAttributeFirstStringValue(UserIdentity.DEFAULT_ATTRIBUTE_GIVENNAME) + " "
                            + sourceUser.getAttributeFirstStringValue(UserIdentity.DEFAULT_ATTRIBUTE_SN));
        }
        if (!destinationIdentity.hasAttribute("displayname")) {
            destinationIdentity.setAttribute("displayname", destinationIdentity.getAttribute("cn"));
        }
        if (!destinationIdentity.hasAttribute("name")) {
            destinationIdentity.setAttribute("name", destinationIdentity.getAttribute("cn"));
        }

        loadIdentityAttributeMail(destinationIdentity, sourceUser);

        /**
         * Custom map
         */
        loadWriteAttributesFromMap(sourceUser, destinationIdentity);

        loadIdentityAttributeAccountStatus(destinationIdentity, sourceUser);
        loadIdentityAttributeManager(destinationIdentity, sourceUser);

        if (sourceUser.hasAttribute(UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD)) {
            destinationIdentity.setAttribute("unicodePwd",
                    sourceUser.getAttribute(UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD));
        }
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
            q.addCondition("objectclass", "person", LDAPDirectoryQuery.EXACT);
            q.addCondition("sAMAccountName", match, LDAPDirectoryQuery.CONTAINS);
            for (final Identity _u : this.directoryManager.sortedSearch(q, "cn")) {
                users.add(getUserIdentity(_u));
            }
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e);
        }
        return users;
    }

    private void storeNewUserIdentity(final UserIdentity actualUser, final String cn) throws IdentityException {
        try {
            final StringBuilder sb = new StringBuilder();
            sb.append("CN=");
            sb.append(cn);
            sb.append(",");
            if (this.defaultUserBranch != null) {
                final StringBuilder branch = new StringBuilder();
                branch.append(this.defaultUserBranch);
                branch.append(",");
                branch.append(this.basedn);
                if (!this.directoryManager.checkIdentity(branch.toString())) {
                    createBranch(branch);
                }
                sb.append(this.defaultUserBranch);
            } else {
                sb.append("CN=Users");
            }
            sb.append(",");
            sb.append(this.basedn);
            final Identity i = new LDAPDirectoryEntry(sb.toString());
            loadIdentityAttributes(i, actualUser);
            if (!this.USER_PASSWORD_NOT_REQUESTED) {
                i.setAttribute(
                        "userAccountControl",
                        Integer.toString(LDAPDirectoryWriter.MSAD_UF_NORMAL_ACCOUNT
                                + LDAPDirectoryWriter.MSAD_UF_PASSWD_NOTREQD));
                this.directoryManager.addIdentity(i, LDAPDirectoryWriter.DIRECTORY_TYPE_MSAD);
                loadIdentityAttributes(i, actualUser);
                if (this.USER_PASSWORD_NEW_MUST_CHANGE) {
                    i.setAttribute(
                            "userAccountControl",
                            Integer.toString(LDAPDirectoryWriter.MSAD_UF_NORMAL_ACCOUNT
                                    + LDAPDirectoryWriter.MSAD_UF_PASSWD_NOTREQD));
                    i.setAttribute("pwdLastSet", Integer.toString(0));
                }
                try {
                    this.directoryManager.updateIdentity(i, LDAPDirectoryWriter.DIRECTORY_TYPE_MSAD);
                } catch (final DirectoryException e) {
                    this.directoryManager.removeIdentity(i.getID());
                    throw e;
                }
            } else {
                if (this.USER_PASSWORD_NEW_MUST_CHANGE) {
                    i.setAttribute("pwdLastSet", Integer.toString(0));
                }
                this.directoryManager.addIdentity(i, LDAPDirectoryWriter.DIRECTORY_TYPE_MSAD);
            }
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e);
        }
    }

    private void storeUserIdentity(final int type, final UserIdentity user) throws IdentityException {
        final UserIdentity actualUser = getUserIdentity(user.getID());
        final String cn = getReadAttributeFromMap(actualUser, UserIdentity.DEFAULT_ATTRIBUTE_CN);

        if (actualUser == null) {
            if (type == MODIFICATION_TYPE_UPDATE) {
                throw new IdentityException("user identity does not exists");
            }
            storeNewUserIdentity(actualUser, cn);
        } else {
            if (type == MODIFICATION_TYPE_ADD) {
                throw new IdentityException("user identity already exists");
            }

            try {
                final Identity i = this.directoryManager.getIdentity(actualUser.getAttributeFirstStringValue("dn"));
                loadIdentityAttributes(i, actualUser);
                this.directoryManager.updateIdentity(i, LDAPDirectoryWriter.DIRECTORY_TYPE_MSAD);
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
