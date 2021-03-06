/*
 * GroupIdentityManagerMSAD class
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

package com.ricardolorenzo.identity.group.impl;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.TreeMap;

import com.ricardolorenzo.directory.DirectoryException;
import com.ricardolorenzo.directory.DirectoryIdentityManager;
import com.ricardolorenzo.directory.ldap.LDAPConnection;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryEntry;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryQuery;
import com.ricardolorenzo.directory.ldap.LDAPDirectoryWriter;
import com.ricardolorenzo.identity.Identity;
import com.ricardolorenzo.identity.IdentityAttributeMap;
import com.ricardolorenzo.identity.IdentityException;
import com.ricardolorenzo.identity.group.GroupIdentity;
import com.ricardolorenzo.identity.group.GroupIdentityManager;
import com.ricardolorenzo.identity.user.UserIdentity;
import com.ricardolorenzo.identity.user.impl.UserIdentityManagerMSAD;

/**
 * 
 * @author Ricardo Lorenzo
 * 
 */
public class GroupIdentityManagerMSAD extends GroupIdentityManager {
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
    private final UserIdentityManagerMSAD userManager;
    private final Properties properties;
    private final String basedn;
    private String timezone;
    private String defaultGroupBranch;

    public GroupIdentityManagerMSAD(final Properties conf) throws DirectoryException {
        super();
        this.properties = conf;
        this.directoryManager = new DirectoryIdentityManager(conf);
        this.userManager = new UserIdentityManagerMSAD(conf);
        if (!this.properties.containsKey("directory.basedn")) {
            throw new DirectoryException("directory basedn not defined [directory.basedn]");
        }
        this.basedn = this.properties.getProperty("directory.basedn");
        if (this.properties.containsKey("directory.timezone")) {
            this.timezone = this.properties.getProperty("directory.timezone");
        }
        if (this.properties.containsKey("directory.group.default_branch")) {
            this.defaultGroupBranch = this.properties.getProperty("directory.group.default_branch");
        }
    }

    @Override
    public void addGroupIdentity(final GroupIdentity group) throws IdentityException {
        storeGroupIdentity(MODIFICATION_TYPE_ADD, group);
    }

    @Override
    public void addGroupUserIdentityMember(final String groupID, final String userID) throws IdentityException {
        if (userID == null) {
            throw new IdentityException("invalid user");
        }
        if (groupID == null) {
            throw new IdentityException("invalid group");
        }
        final GroupIdentity group = getGroupIdentity(groupID);
        if (group == null) {
            throw new IdentityException("group [" + groupID + "] does not exists");
        }
        final Identity user = this.userManager.getUserBasicIdentity(userID);
        if (user == null) {
            throw new IdentityException("user [" + userID + "] does not exists");
        }
        try {
            this.directoryManager
                    .addIdentityAttribute(group.getAttributeFirstStringValue("dn"), "member", user.getID());
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e.getMessage());
        }
    }

    private void createBranch(final StringBuilder branch) throws DirectoryException {
        final String _name = getOrganizationalUnitName(branch.toString());
        final Identity i = new LDAPDirectoryEntry(branch.toString());
        i.setAttribute("objectClass", new String[] { "top", "organizationalUnit" });
        i.setAttribute("distinguishedName", branch.toString());
        i.setAttribute("instanceType", "4");
        i.setAttribute("objectCategory", "CN=Organizational-Unit,CN=Schema,CN=Configuration," + this.basedn);
        i.setAttribute("ou", _name);
        i.setAttribute("name", _name);
        this.directoryManager.addIdentity(i);
    }

    @Override
    public void deleteGroupIdentity(final GroupIdentity group) throws IdentityException {
        final GroupIdentity actualGroup = getGroupIdentity(group.getID());
        if (actualGroup != null) {
            try {
                this.directoryManager.removeIdentity(actualGroup.getID());
            } catch (final DirectoryException e) {
                throw new IdentityException(e);
            }
        } else {
            throw new IdentityException("group does not exists");
        }
    }

    private GroupIdentity getGroupIdentity(final Identity group) throws IdentityException {
        final GroupIdentity sourceGroup = new GroupIdentity(group);
        final GroupIdentity destinationGroup = new GroupIdentity(new LDAPDirectoryEntry(sourceGroup.getID()));
        destinationGroup.setAttribute("dn", sourceGroup.getID());
        loadAttributesFromMap(IdentityAttributeMap.getDefaultReadMap(), sourceGroup, destinationGroup);

        /**
         * Load attributes from custom map
         */
        loadReadAttributesFromMap(sourceGroup, destinationGroup);

        /**
         * Load the modification time
         */
        if (sourceGroup.hasAttribute("whenChanged")) {
            final Calendar lastModified = getMSADCalendarAttribute(sourceGroup
                    .getAttributeFirstStringValue("whenChanged"));
            destinationGroup.setAttribute(GroupIdentity.DEFAULT_ATTRIBUTE_LASTMODIFED,
                    Identity.getLastModifiedString(lastModified));
        }
        return destinationGroup;
    }

    @Override
    public GroupIdentity getGroupIdentity(final String group) throws IdentityException {
        if (group == null) {
            return null;
        }
        final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
        try {
            this.directoryManager.setScope(LDAPConnection.SUBTREE_SCOPE);
            q.addCondition("objectclass", "group", LDAPDirectoryQuery.EXACT);
            q.addCondition("name", group, LDAPDirectoryQuery.EXACT);
            final List<Identity> _result = this.directoryManager.searchIdentities(q);
            if ((_result != null) && !_result.isEmpty()) {
                return getGroupIdentity(_result.get(0));
            }
        } catch (final DirectoryException e) {
            throw new IdentityException(e);
        }
        return null;
    }

    @Override
    public List<GroupIdentity> getGroupIdentityMembers(final GroupIdentity group, final boolean recursive)
            throws IdentityException {
        final Map<String, GroupIdentity> groups = new TreeMap<String, GroupIdentity>(Collator.getInstance());
        final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
        q.addCondition("objectclass", "group", LDAPDirectoryQuery.EXACT);
        q.addCondition("name", group, LDAPDirectoryQuery.EXACT);
        List<Identity> results = null;
        try {
            results = this.directoryManager.searchIdentities(q);
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e.getMessage());
        }
        if ((results != null) && !results.isEmpty()) {
            final GroupIdentity matchGroup = getGroupIdentity(results.get(0));
            final List<String> checkedGroups = new ArrayList<String>();
            getGroupMembers(matchGroup, checkedGroups, recursive, groups);
        }
        return new ArrayList<GroupIdentity>(groups.values());
    }

    @Override
    public List<UserIdentity> getGroupIdentityUserMembers(final GroupIdentity group, final boolean recursive)
            throws IdentityException {
        final Map<String, UserIdentity> users = new TreeMap<String, UserIdentity>(Collator.getInstance());
        final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
        q.addCondition("objectclass", "group", LDAPDirectoryQuery.EXACT);
        q.addCondition("name", group, LDAPDirectoryQuery.EXACT);
        List<Identity> results = null;
        try {
            results = this.directoryManager.searchIdentities(q);
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e.getMessage());
        }
        if ((results != null) && !results.isEmpty()) {
            final GroupIdentity matchGroup = getGroupIdentity(results.get(0));
            final List<String> checkedGroups = new ArrayList<String>();
            getGroupUserMembers(matchGroup, checkedGroups, recursive, users);
        }
        return new ArrayList<UserIdentity>(users.values());
    }

    private void getGroupMembers(final GroupIdentity group, final List<String> checkedGroups, final boolean recursive,
            final Map<String, GroupIdentity> groups) throws IdentityException {
        if (group.hasAttribute("member")) {
            for (final Object o : group.getAttribute("member")) {
                try {
                    final Identity i = this.directoryManager.getIdentity(String.valueOf(o));
                    if (i.hasAttributeValue("objectClass", "group") && !i.hasAttribute("sAMAccountName")) {
                        final GroupIdentity memberGroup = getGroupIdentity(i);
                        groups.put(group.getID(), memberGroup);
                    }
                } catch (final DirectoryException e) {
                    // nothing
                }
            }
        }
        if (recursive) {
            for (final GroupIdentity memberGroup : getGroupIdentityMembers(group, recursive)) {
                if (!checkedGroups.contains(memberGroup.getID())) {
                    getGroupMembers(memberGroup, checkedGroups, recursive, groups);
                    checkedGroups.add(memberGroup.getID());
                }
            }
        }
    }

    private void getGroupUserMembers(final GroupIdentity group, final List<String> checkedGroups,
            final boolean recursive, final Map<String, UserIdentity> users) throws IdentityException {
        if (group.hasAttribute("member")) {
            for (final Object o : group.getAttribute("member")) {
                try {
                    final Identity i = this.directoryManager.getIdentity(String.valueOf(o));
                    if (i.hasAttributeValue("objectClass", "person") && i.hasAttribute("sAMAccountName")) {
                        final UserIdentity user = this.userManager.getUserIdentity(i);
                        users.put(user.getID(), user);
                    }
                } catch (final DirectoryException e) {
                    // nothing
                }
            }
        }
        if (recursive) {
            for (final GroupIdentity memberGroup : getGroupIdentityMembers(group, recursive)) {
                if (!checkedGroups.contains(memberGroup.getID())) {
                    getGroupUserMembers(memberGroup, checkedGroups, recursive, users);
                    checkedGroups.add(memberGroup.getID());
                }
            }
        }
    }

    @Override
    public List<GroupIdentity> getModifiedGroupIdentities(final Calendar date) throws IdentityException {
        // TODO Auto-generated method stub
        return null;
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

    @Override
    public List<GroupIdentity> getUserGroupIdentities(final UserIdentity user) throws IdentityException {
        // TODO Auto-generated method stub
        return null;
    }

    private void loadIdentityAttributes(final Identity destinationIdentity, final GroupIdentity sourceGroup)
            throws DirectoryException, IdentityException {
        loadAttributesFromMap(IdentityAttributeMap.getDefaultWriteMap(), sourceGroup, destinationIdentity);

        if (!destinationIdentity.hasAttribute("objectclass")) {
            destinationIdentity.setAttribute("objectclass", new String[] { "top", "group" });
        }

        loadAttributesFromMap(IdentityAttributeMap.getDefaultWriteMap(), sourceGroup, destinationIdentity);

        if (!destinationIdentity.hasAttribute("cn")) {
            throw new IdentityException("cn attribute not defined for group");
        }
        if (!destinationIdentity.hasAttribute("name")) {
            destinationIdentity.setAttribute("name", destinationIdentity.getAttribute("cn"));
        }

        /**
         * Custom map
         */
        loadWriteAttributesFromMap(sourceGroup, destinationIdentity);
    }

    @Override
    public void removeUserMember(final String groupID, final String userID) throws Exception {
        if (userID == null) {
            throw new IdentityException("invalid user");
        }
        if (groupID == null) {
            throw new IdentityException("invalid group");
        }
        final GroupIdentity group = getGroupIdentity(groupID);
        if (group == null) {
            throw new IdentityException("group [" + groupID + "] does not exists");
        }
        final Identity user = this.userManager.getUserBasicIdentity(userID);
        if (user == null) {
            throw new IdentityException("user [" + userID + "] does not exists");
        }
        try {
            this.directoryManager.removeIdentityAttribute(group.getAttributeFirstStringValue("dn"), "member",
                    user.getID());
        } catch (final DirectoryException e) {
            if (!((e.getMessage() != null) && (e.getMessage().contains("attribute [member] not found in entry") || e
                    .getMessage().contains("WILL_NOT_PERFORM")))) {
                logError(e);
                throw new IdentityException(e.getMessage());
            }
        }
    }

    @Override
    public List<GroupIdentity> searchGroup(final String match) throws Exception {
        final List<GroupIdentity> groups = new ArrayList<GroupIdentity>();
        if (match == null) {
            return groups;
        }
        try {
            final LDAPDirectoryQuery q = new LDAPDirectoryQuery();
            this.directoryManager.setScope(LDAPConnection.SUBTREE_SCOPE);
            q.addCondition("objectclass", "group", LDAPDirectoryQuery.EXACT);
            q.addCondition("name", match, LDAPDirectoryQuery.CONTAINS);
            for (final Identity group : this.directoryManager.sortedSearch(q, "name")) {
                groups.add(getGroupIdentity(group));
            }
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e);
        }
        return groups;
    }

    private void storeGroupIdentity(final int type, final GroupIdentity group) throws IdentityException {
        final GroupIdentity actualGroup = getGroupIdentity(group.getID());
        final String cn = getReadAttributeFromMap(actualGroup, GroupIdentity.DEFAULT_ATTRIBUTE_CN);

        if (actualGroup == null) {
            if (type == MODIFICATION_TYPE_UPDATE) {
                throw new IdentityException("group does not exists");
            }
            storeNewGroupIdentity(actualGroup, cn);
        } else {
            if (type == MODIFICATION_TYPE_ADD) {
                throw new IdentityException("group already exists");
            }

            try {
                final Identity i = this.directoryManager.getIdentity(actualGroup.getAttributeFirstStringValue("dn"));
                loadIdentityAttributes(i, actualGroup);
                this.directoryManager.updateIdentity(i, LDAPDirectoryWriter.DIRECTORY_TYPE_MSAD);
            } catch (final DirectoryException e) {
                logError(e);
                throw new IdentityException(e);
            }
        }
    }

    private void storeNewGroupIdentity(final GroupIdentity actualGroup, final String cn) throws IdentityException {
        try {
            final StringBuilder sb = new StringBuilder();
            sb.append("CN=");
            sb.append(cn);
            sb.append(",");
            if (this.defaultGroupBranch != null) {
                final StringBuilder branch = new StringBuilder();
                branch.append(this.defaultGroupBranch);
                branch.append(",");
                branch.append(this.basedn);
                if (!this.directoryManager.checkIdentity(branch.toString())) {
                    createBranch(branch);
                }
                sb.append(this.defaultGroupBranch);
            } else {
                sb.append("CN=Users");
            }
            sb.append(",");
            sb.append(this.basedn);
            final Identity i = new LDAPDirectoryEntry(sb.toString());
            loadIdentityAttributes(i, actualGroup);
            this.directoryManager.addIdentity(i, LDAPDirectoryWriter.DIRECTORY_TYPE_MSAD);
        } catch (final DirectoryException e) {
            logError(e);
            throw new IdentityException(e);
        }
    }

    @Override
    public void updateGroup(final GroupIdentity group) throws Exception {
        storeGroupIdentity(MODIFICATION_TYPE_ANY, group);
    }
}
