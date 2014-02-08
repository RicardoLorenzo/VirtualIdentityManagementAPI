package com.ricardolorenzo.identity.group;

import java.util.ArrayList;
import java.util.List;

import com.ricardolorenzo.identity.Identity;
import com.ricardolorenzo.identity.user.UserIdentity;

public class GroupIdentity extends Identity {
    private static final long serialVersionUID = 8909342089053659975L;

    public static final String DEFAULT_ATTRIBUTE_CN = "cn";
    public static final String DEFAULT_ATTRIBUTE_DESCRIPTION = "description";
    public static final String DEFAULT_ATTRIBUTE_COMPANY = "o";
    public static final String DEFAULT_ATTRIBUTE_OU = "ou";
    public static final String DEFAULT_ATTRIBUTE_LASTMODIFED = "lastModified";

    public GroupIdentity() {
        super();
    }

    public GroupIdentity(final Identity identity) {
        super();
        setAttributes(identity.getAttributes());
    }

    public boolean attributeContainsGroupIdentity(final String attributeName) {
        if (hasAttribute(attributeName)) {
            for (Object o : getAttribute(attributeName)) {
                if (o instanceof UserIdentity) {
                    return true;
                }
            }
        }
        return false;
    }

    public List<GroupIdentity> getAttributeGroupIdentity(final String attributeName) {
        List<GroupIdentity> values = new ArrayList<GroupIdentity>();
        if (hasAttribute(attributeName)) {
            for (Object o : getAttribute(attributeName)) {
                if (o instanceof GroupIdentity) {
                    values.add((GroupIdentity) o);
                }
            }
        }
        return values;
    }

    public static boolean isDefaultAttribute(String attribute) {
        if (attribute == null) {
            return false;
        }
        if (DEFAULT_ATTRIBUTE_CN.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_DESCRIPTION.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_COMPANY.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_OU.equals(attribute)) {
            return true;
        }
        return false;
    }

    public void setAttributes(final GroupIdentity group) {
        setAttributes(group.getAttributes());
    }
}
