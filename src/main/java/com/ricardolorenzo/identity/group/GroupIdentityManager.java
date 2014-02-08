package com.ricardolorenzo.identity.group;

import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.logging.Logger;

import com.ricardolorenzo.directory.DirectoryException;
import com.ricardolorenzo.identity.Identity;
import com.ricardolorenzo.identity.IdentityAttributeMap;
import com.ricardolorenzo.identity.IdentityException;
import com.ricardolorenzo.identity.group.impl.GroupIdentityManagerMSAD;
import com.ricardolorenzo.identity.script.ScriptCollection;
import com.ricardolorenzo.identity.user.UserIdentity;

public abstract class GroupIdentityManager {
    public static final String GROUP_MANAGER_LDAPv3 = "ldap";
    public static final String GROUP_MANAGER_MSAD = "msad";
    public static final String GROUP_MANAGER_JDBC = "jdbc";

    public static final int STORE_FLEXIBLE = 1;
    public static final int STORE_ADD_ONLY = 2;
    public static final int STORE_UPDATE_ONLY = 3;

    private IdentityAttributeMap attributeMap;
    private ScriptCollection scripts;

    public abstract void addGroupIdentity(GroupIdentity group) throws IdentityException;

    public abstract void addGroupUserIdentityMember(GroupIdentity group, UserIdentity user) throws IdentityException;

    public abstract void addGroupUserIdentityMember(String group, String user) throws IdentityException;

    public abstract void deleteGroupIdentity(GroupIdentity group) throws IdentityException;

    private final String getAttributeFromMap(final Map<String, String> attributeMap, final Identity group,
            final String attributeName) throws IdentityException {
        if (attributeName == null) {
            return null;
        }
        if (attributeMap.containsKey(attributeName)) {
            return getSmartContent(attributeMap.get(attributeName), group);
        } else if (group.hasAttribute(attributeName)) {
            return group.getAttributeFirstStringValue(attributeName);
        }
        return null;
    }

    public abstract List<GroupIdentity> getModifiedGroupIdentities(Calendar date) throws IdentityException;

    public static final GroupIdentityManager getInstance(Properties conf, final IdentityAttributeMap attributeMap,
            final ScriptCollection scripts) throws IdentityException {
        if (conf == null) {
            throw new IdentityException("invalid user identity manager configuration");
        }

        GroupIdentityManager identityManager = null;
        switch (conf.getProperty("type")) {
            default: {
                throw new IdentityException("invalid user identity manager type");
            }
            case GROUP_MANAGER_LDAPv3: {
                // try {
                // identityManager = new GroupIdentityManagerLDAPv3(conf);
                // } catch (final DirectoryException e) {
                /**
                 * TODO log this
                 */
                // }
                break;
            }
            case GROUP_MANAGER_MSAD: {
                try {
                    identityManager = new GroupIdentityManagerMSAD(conf);
                } catch (final DirectoryException e) {
                    /**
                     * TODO log this
                     */
                }
                break;
            }
            case GROUP_MANAGER_JDBC: {
                // try {
                // identityManager = new GroupIdentityManagerDatabase(conf);
                // } catch (final DBException e) {
                /**
                 * TODO log this
                 */
                // }
                break;
            }
        }
        identityManager.setAttributeMap(attributeMap);
        identityManager.setScriptCollection(scripts);
        return identityManager;
    }

    /**
     * Get the group groups members
     * 
     * @param group
     *            Group for looking members
     * @param recursive
     *            Get all the user members for nested groups
     * @return
     * @throws IdentityException
     */
    public abstract List<GroupIdentity> getGroupIdentityMembers(GroupIdentity group, boolean recursive)
            throws IdentityException;

    /**
     * Get the group groups members names
     * 
     * @param group
     *            Group for looking members
     * @param recursive
     *            Get all the user members for nested groups
     * @return
     * @throws IdentityException
     */
    public abstract List<String> getGroupIdentityMemberNames(GroupIdentity group, boolean recursive)
            throws IdentityException;

    /**
     * Get the group user members
     * 
     * @param group
     *            Group for looking members
     * @param recursive
     *            Get all the user members for nested groups
     * @return
     * @throws IdentityException
     */
    public abstract List<UserIdentity> getGroupIdentityUserMembers(GroupIdentity group, boolean recursive)
            throws IdentityException;

    /**
     * Get the group user members names
     * 
     * @param group
     *            Group for looking members
     * @param recursive
     *            Get all the user members for nested groups
     * @return
     * @throws IdentityException
     */
    public abstract List<String> getGroupIdentityUserMemberNames(GroupIdentity group, boolean recursive)
            throws IdentityException;

    /**
     * Get the groups for a specific user
     * 
     * @param group
     *            Group for looking members
     * @param recursive
     *            Get all the user members for nested groups
     * @return
     * @throws IdentityException
     */
    public abstract List<GroupIdentity> getUserGroupIdentities(UserIdentity user) throws IdentityException;

    /**
     * Get the groups for a specific user
     * 
     * @param group
     *            Group for looking members
     * @param recursive
     *            Get all the user members for nested groups
     * @return
     * @throws IdentityException
     */
    public abstract List<GroupIdentity> getUserGroupIdentityNames(UserIdentity user) throws IdentityException;

    public abstract List<Identity> getModifiedGroups(Calendar date) throws IdentityException;

    public abstract GroupIdentity getGroupIdentity(String group) throws IdentityException;

    protected final String getReadAttributeFromMap(final Identity group, final String attributeName)
            throws IdentityException {
        return getAttributeFromMap(this.attributeMap.getReadMap(), group, attributeName);
    }

    protected final String getWriteAttributeFromMap(final Identity group, final String attributeName)
            throws IdentityException {
        return getAttributeFromMap(this.attributeMap.getWriteMap(), group, attributeName);
    }

    protected final ScriptCollection getScriptCollection() throws IdentityException {
        return this.scripts;
    }

    protected String getSmartContent(String content, Identity user) throws IdentityException {
        if (content == null || content.isEmpty()) {
            throw new IdentityException("invalid request content");
        }
        int _old_offset = 0;
        StringBuilder sb = new StringBuilder();
        for (int _offset = content.indexOf("[[[", 0); _offset != -1; _offset = content.indexOf("[[[", _offset)) {
            sb.append(content.substring(_old_offset, _offset));
            _offset += 3;
            if (content.indexOf("]]]", _offset) != -1) {
                String _name = content.substring(_offset, content.indexOf("]]]", _offset));
                if (user != null && user.hasAttribute(_name)) {
                    sb.append(user.getAttributeFirstStringValue(_name));
                } else {
                    sb.append("");
                }
                _old_offset = content.indexOf("]]]", _offset) + 3;
            }
        }
        sb.append(content.substring(_old_offset, content.length()));
        return sb.toString();
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

    public abstract void removeUserMember(String groupID, String userID) throws Exception;

    public abstract List<Identity> searchGroup(String match) throws Exception;

    public abstract void updateGroup(GroupIdentity group) throws Exception;
}
