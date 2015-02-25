/*
 * UserIdentityManager class
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
package com.ricardolorenzo.identity.user;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.logging.Logger;

import com.ricardolorenzo.db.DBException;
import com.ricardolorenzo.directory.DirectoryException;
import com.ricardolorenzo.identity.Identity;
import com.ricardolorenzo.identity.IdentityAttributeMap;
import com.ricardolorenzo.identity.IdentityException;
import com.ricardolorenzo.identity.script.ScriptCollection;
import com.ricardolorenzo.identity.security.Base64;
import com.ricardolorenzo.identity.user.impl.UserIdentityManagerJDBCDatabase;
import com.ricardolorenzo.identity.user.impl.UserIdentityManagerLDAP;
import com.ricardolorenzo.identity.user.impl.UserIdentityManagerMSAD;

public abstract class UserIdentityManager {
    public static final String USER_MANAGER_LDAPv3 = "ldap";
    public static final String USER_MANAGER_MSAD = "msad";
    public static final String USER_MANAGER_JDBC = "jdbc";

    public static final int STORE_FLEXIBLE = 1;
    public static final int STORE_ADD_ONLY = 2;
    public static final int STORE_UPDATE_ONLY = 3;

    public static final int PASSWORD_CLEAR = 1;
    public static final int PASSWORD_CRYPT = 2;
    public static final int PASSWORD_MD2_BASE64 = 3;
    public static final int PASSWORD_MD5_BASE64 = 4;
    public static final int PASSWORD_SHA1_BASE64 = 5;
    public static final int PASSWORD_SHA256_BASE64 = 6;
    public static final int PASSWORD_SHA384_BASE64 = 7;
    public static final int PASSWORD_SHA512_BASE64 = 8;

    /**
     * Generate a base64 string with the password hash
     * 
     * @param password
     * @param algorithm
     * @return Base64 string with the password hash
     * @throws NoSuchAlgorithmException
     * @throws IdentityException
     */
    private static String generateMessageDigest(final String password, final String algorithm)
            throws NoSuchAlgorithmException, IdentityException {
        if (password == null) {
            return null;
        } else if (algorithm == null) {
            return null;
        }

        MessageDigest md = null;
        final StringBuilder digest = new StringBuilder();
        md = MessageDigest.getInstance(algorithm);
        md.reset();
        md.update(password.getBytes());
        md.update(new byte[0]);
        digest.append(Base64.encode(md.digest()));
        return digest.toString();
    }

    protected final static String getEncriptedPassword(final int type, final String password, final boolean prefix)
            throws NoSuchAlgorithmException, IdentityException {
        if (password == null) {
            return password;
        }
        switch (type) {
            case PASSWORD_CLEAR: {
                return password;
            }
            case PASSWORD_CRYPT: {
                throw new IdentityException("unix crypt not implemented");
            }
            case PASSWORD_MD2_BASE64: {
                final StringBuilder sb = new StringBuilder();
                if (prefix) {
                    sb.append("{MD2}");
                }
                sb.append(generateMessageDigest(password, "MD2"));
                return sb.toString();
            }
            case PASSWORD_MD5_BASE64: {
                final StringBuilder sb = new StringBuilder();
                if (prefix) {
                    sb.append("{MD5}");
                }
                sb.append(generateMessageDigest(password, "MD5"));
                return sb.toString();
            }
            case PASSWORD_SHA1_BASE64: {
                final StringBuilder sb = new StringBuilder();
                if (prefix) {
                    sb.append("{SHA}");
                }
                sb.append(generateMessageDigest(password, "SHA-1"));
                return sb.toString();
            }
            case PASSWORD_SHA256_BASE64: {
                final StringBuilder sb = new StringBuilder();
                if (prefix) {
                    sb.append("{SHA256}");
                }
                sb.append(generateMessageDigest(password, "SHA-256"));
                return sb.toString();
            }
            case PASSWORD_SHA384_BASE64: {
                final StringBuilder sb = new StringBuilder();
                if (prefix) {
                    sb.append("{SHA384}");
                }
                sb.append(generateMessageDigest(password, "SHA-384"));
                return sb.toString();
            }
            case PASSWORD_SHA512_BASE64: {
                final StringBuilder sb = new StringBuilder();
                if (prefix) {
                    sb.append("{SHA512}");
                }
                sb.append(generateMessageDigest(password, "SHA-512"));
                return sb.toString();
            }
            default:
                break;
        }
        return password;
    }

    public static final UserIdentityManager getInstance(final Properties conf, final IdentityAttributeMap attributeMap,
            final ScriptCollection scripts) throws IdentityException {
        if (conf == null) {
            throw new IdentityException("invalid user identity manager configuration");
        }

        UserIdentityManager identityManager = null;
        switch (conf.getProperty("identity.type")) {
            default: {
                throw new IdentityException("invalid user identity manager type");
            }
            case USER_MANAGER_LDAPv3: {
                try {
                    identityManager = new UserIdentityManagerLDAP(conf);
                } catch (final DirectoryException e) {
                    /**
                     * TODO log this
                     */
                }
                break;
            }
            case USER_MANAGER_MSAD: {
                try {
                    identityManager = new UserIdentityManagerMSAD(conf);
                } catch (final DirectoryException e) {
                    /**
                     * TODO log this
                     */
                }
                break;
            }
            case USER_MANAGER_JDBC: {
                try {
                    identityManager = new UserIdentityManagerJDBCDatabase(conf);
                } catch (final DBException e) {
                    /**
                     * TODO log this
                     */
                }
                break;
            }
        }
        setPasswordEncription(conf, identityManager);
        identityManager.setAttributeMap(attributeMap);
        identityManager.setScriptCollection(scripts);
        return identityManager;
    }

    protected static final List<String> getList(final String text) {
        final List<String> list = new ArrayList<String>();
        if (text == null) {
            return list;
        } else if (text.contains("\n")) {
            for (String token : text.split("\n")) {
                token = token.trim();
                if (!token.isEmpty()) {
                    list.add(token);
                }
            }
        } else if (text.contains(",")) {
            for (String token : text.split(",")) {
                token = token.trim();
                if (!token.isEmpty()) {
                    list.add(token);
                }
            }
        } else if (text.contains(" ")) {
            for (String token : text.split("\\ ")) {
                token = token.trim();
                if (!token.isEmpty()) {
                    list.add(token);
                }
            }
        } else if (!text.isEmpty()) {
            list.add(text);
        }
        return list;
    }

    public static final boolean isPasswordEncriptionType(final int type) {
        switch (type) {
            case PASSWORD_CLEAR: {
                return true;
            }
            case PASSWORD_CRYPT: {
                return true;
            }
            case PASSWORD_MD2_BASE64: {
                return true;
            }
            case PASSWORD_MD5_BASE64: {
                return true;
            }
            case PASSWORD_SHA1_BASE64: {
                return true;
            }
            case PASSWORD_SHA256_BASE64: {
                return true;
            }
            case PASSWORD_SHA384_BASE64: {
                return true;
            }
            case PASSWORD_SHA512_BASE64: {
                return true;
            }
            default:
                break;
        }
        return false;
    }

    private static void setPasswordEncription(final Properties conf, final UserIdentityManager identityManager)
            throws IdentityException {
        if (conf.containsKey("identity.password.encription")) {
            switch (conf.getProperty("identity.password.encription")) {
                case "clear": {
                    identityManager.passwordEncription = UserIdentityManager.PASSWORD_CLEAR;
                    break;
                }
                case "crypt": {
                    throw new IdentityException("unix crypt not implemented");
                }
                case "md2": {
                    identityManager.passwordEncription = UserIdentityManager.PASSWORD_MD2_BASE64;
                    break;
                }
                case "md5": {
                    identityManager.passwordEncription = UserIdentityManager.PASSWORD_MD5_BASE64;
                    break;
                }
                case "sha1": {
                    identityManager.passwordEncription = UserIdentityManager.PASSWORD_SHA1_BASE64;
                    break;
                }
                case "sha256": {
                    identityManager.passwordEncription = UserIdentityManager.PASSWORD_SHA256_BASE64;
                    break;
                }
                case "sha384": {
                    identityManager.passwordEncription = UserIdentityManager.PASSWORD_SHA384_BASE64;
                    break;
                }
                case "sha512": {
                    identityManager.passwordEncription = UserIdentityManager.PASSWORD_SHA512_BASE64;
                    break;
                }
                default:
                    throw new IdentityException("invalid password encription type [identity.password.encription]: "
                            + conf.getProperty("identity.password.encription"));
            }
        } else {
            identityManager.passwordEncription = UserIdentityManager.PASSWORD_CLEAR;
        }
    }

    protected int passwordEncription;

    private IdentityAttributeMap attributeMap;

    private ScriptCollection scripts;

    /**
     * Add a user
     * 
     * @param user
     * @throws IdentityException
     */
    public abstract void addUserIdentity(UserIdentity user) throws IdentityException;

    /**
     * Delete a user
     * 
     * @param user
     * @throws IdentityException
     */
    public abstract void deleteUserIdentity(UserIdentity user) throws IdentityException;

    private final String getAttributeFromMap(final Map<String, String> attributeMap, final Identity user,
            final String attributeName) throws IdentityException {
        if (attributeName == null) {
            return null;
        }
        if (attributeMap.containsKey(attributeName)) {
            return getSmartContent(attributeMap.get(attributeName), user);
        } else if (user.hasAttribute(attributeName)) {
            return user.getAttributeFirstStringValue(attributeName);
        }
        return null;
    }

    protected final String getEncriptedPassword(final String password, final boolean prefix)
            throws NoSuchAlgorithmException, IdentityException {
        return getEncriptedPassword(this.passwordEncription, password, prefix);
    }

    public abstract List<UserIdentity> getModifiedUserIdentities(Calendar date) throws IdentityException;

    protected final String getReadAttributeFromMap(final Identity user, final String attributeName)
            throws IdentityException {
        return getAttributeFromMap(this.attributeMap.getReadMap(), user, attributeName);
    }

    protected final ScriptCollection getScriptCollection() throws IdentityException {
        return this.scripts;
    }

    protected final String getSmartContent(final String content, final Identity user) throws IdentityException {
        if ((content == null) || content.isEmpty()) {
            throw new IdentityException("invalid request content");
        }
        int oldOffset = 0;
        final StringBuilder contentOutput = new StringBuilder();
        for (int offset = content.indexOf("[[[", 0); offset != -1; offset = content.indexOf("[[[", offset)) {
            contentOutput.append(content.substring(oldOffset, offset));
            offset += 3;
            if (content.indexOf("]]]", offset) != -1) {
                final String attributeName = content.substring(offset, content.indexOf("]]]", offset));
                if ((user != null) && user.hasAttribute(attributeName)) {
                    if (UserIdentity.DEFAULT_ATTRIBUTE_PASSWORD.equals(attributeName)) {
                        try {
                            contentOutput.append(getEncriptedPassword(user.getAttributeFirstStringValue(attributeName),
                                    false));
                        } catch (final NoSuchAlgorithmException e) {
                            throw new IdentityException("invalid password encryption algorithm");
                        }
                    } else if (user.hasAttribute(attributeName)) {
                        contentOutput.append(user.getAttributeFirstStringValue(attributeName));
                    }
                }
                oldOffset = content.indexOf("]]]", offset) + 3;
            }
        }
        contentOutput.append(content.substring(oldOffset, content.length()));
        return contentOutput.toString();
    }

    public abstract UserIdentity getUserIdentity(String user) throws IdentityException;

    protected final String getWriteAttributeFromMap(final Identity user, final String attributeName)
            throws IdentityException {
        return getAttributeFromMap(this.attributeMap.getWriteMap(), user, attributeName);
    }

    protected final void loadAttributesFromMap(final Map<String, String> attributeMap, final Identity sourceUser,
            final Identity destinationUser) throws IdentityException {
        for (final Entry<String, String> e : attributeMap.entrySet()) {
            final String value = getAttributeFromMap(attributeMap, sourceUser, e.getKey());
            if ((value != null) && !value.isEmpty()) {
                destinationUser.setAttribute(e.getKey(), value);
            } else {
                destinationUser.removeAttribute(e.getKey());
            }
        }
    }

    protected final void loadReadAttributesFromMap(final Identity sourceUser, final Identity destinationUser)
            throws IdentityException {
        loadAttributesFromMap(this.attributeMap.getReadMap(), sourceUser, destinationUser);
    }

    protected final void loadWriteAttributesFromMap(final Identity sourceUser, final Identity destinationUser)
            throws IdentityException {
        loadAttributesFromMap(this.attributeMap.getWriteMap(), sourceUser, destinationUser);
    }

    protected final void logError(final Exception e) {
        logError(e.getMessage(), e);
    }

    protected final void logError(final String message, final Exception e) {
        final Logger log = Logger.getLogger(getClass().getName());
        log.log(java.util.logging.Level.SEVERE, message, e);
    }

    protected final void logWarning(final Exception e) {
        logWarning(e.getMessage(), e);
    }

    protected final void logWarning(final String message, final Exception e) {
        final Logger log = Logger.getLogger(getClass().getName());
        log.log(java.util.logging.Level.WARNING, message, e);
    }

    public abstract List<UserIdentity> searchUserIdentity(String match) throws IdentityException;

    private void setAttributeMap(final IdentityAttributeMap attributeMap) {
        if (attributeMap != null) {
            this.attributeMap = attributeMap;
        } else {
            this.attributeMap = new IdentityAttributeMap();
        }
    }

    private void setScriptCollection(final ScriptCollection scripts) {
        if (this.attributeMap != null) {
            this.scripts = scripts;
        } else {
            this.scripts = new ScriptCollection();
        }
    }

    public abstract void updateUserIdentity(UserIdentity user) throws IdentityException;
}
