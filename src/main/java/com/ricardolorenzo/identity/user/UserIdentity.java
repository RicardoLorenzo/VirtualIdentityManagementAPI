/*
 * UserIdentity class
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

import java.util.ArrayList;
import java.util.List;

import com.ricardolorenzo.identity.Identity;

/**
 * 
 * @author Ricardo Lorenzo
 * 
 */
public class UserIdentity extends Identity {
    private static final long serialVersionUID = 8909342089053659975L;

    public static final String DEFAULT_ATTRIBUTE_UID = "uid";
    public static final String DEFAULT_ATTRIBUTE_CN = "cn";
    public static final String DEFAULT_ATTRIBUTE_GIVENNAME = "givenName";
    public static final String DEFAULT_ATTRIBUTE_SN = "sn";
    public static final String DEFAULT_ATTRIBUTE_LASTMODIFED = "lastModified";
    public static final String DEFAULT_ATTRIBUTE_DISPLAYNAME = "displayname";
    public static final String DEFAULT_ATTRIBUTE_ACCOUNT = "accountStatus";
    public static final String DEFAULT_ATTRIBUTE_DESCRIPTION = "description";
    public static final String DEFAULT_ATTRIBUTE_MAIL = "mail";
    public static final String DEFAULT_ATTRIBUTE_MAILDROP = "maildrop";
    public static final String DEFAULT_ATTRIBUTE_TITLE = "title";
    public static final String DEFAULT_ATTRIBUTE_COMPANY = "o";
    public static final String DEFAULT_ATTRIBUTE_OU = "ou";
    public static final String DEFAULT_ATTRIBUTE_DEPARTMENT = "ou";
    public static final String DEFAULT_ATTRIBUTE_STREETADDRESS = "streetAddress";
    public static final String DEFAULT_ATTRIBUTE_POSTALCODE = "postalcode";
    public static final String DEFAULT_ATTRIBUTE_STATE = "st";
    public static final String DEFAULT_ATTRIBUTE_LOCALITY = "l";
    public static final String DEFAULT_ATTRIBUTE_COUNTRY = "c";
    public static final String DEFAULT_ATTRIBUTE_EMPLOYEETYPE = "employeetype";
    public static final String DEFAULT_ATTRIBUTE_TELEPHONENUMBER = "telephoneNumber";
    public static final String DEFAULT_ATTRIBUTE_MOBILE = "mobile";
    public static final String DEFAULT_ATTRIBUTE_FACSIMILETELEPHONENUMBER = "facsimileTelephoneNumber";
    public static final String DEFAULT_ATTRIBUTE_MANAGER = "manager";
    public static final String DEFAULT_ATTRIBUTE_HOMEDRIVE = "homeDrive";
    public static final String DEFAULT_ATTRIBUTE_HOMEDIRECTORY = "homeDirectory";
    public static final String DEFAULT_ATTRIBUTE_PROFILEPATH = "profilePath";
    public static final String DEFAULT_ATTRIBUTE_SCRIPTPATH = "scriptPath";
    public static final String DEFAULT_ATTRIBUTE_PASSWORD = "password";

    public UserIdentity() {
        super();
    }

    public UserIdentity(final Identity identity) {
        super();
        setAttributes(identity.getAttributes());
    }

    public boolean attributeContainsUserIdentity(final String attributeName) {
        if (hasAttribute(attributeName)) {
            for (Object o : getAttribute(attributeName)) {
                if (o instanceof UserIdentity) {
                    return true;
                }
            }
        }
        return false;
    }

    public List<UserIdentity> getAttributeUserIdentity(final String attributeName) {
        List<UserIdentity> values = new ArrayList<UserIdentity>();
        if (hasAttribute(attributeName)) {
            for (Object o : getAttribute(attributeName)) {
                if (o instanceof UserIdentity) {
                    values.add((UserIdentity) o);
                }
            }
        }
        return values;
    }

    public static boolean isDefaultAttribute(String attribute) {
        if (attribute == null) {
            return false;
        }
        if (DEFAULT_ATTRIBUTE_UID.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_CN.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_GIVENNAME.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_SN.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_DISPLAYNAME.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_ACCOUNT.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_DESCRIPTION.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_MAIL.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_MAILDROP.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_TITLE.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_COMPANY.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_OU.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_DEPARTMENT.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_STREETADDRESS.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_POSTALCODE.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_STATE.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_LOCALITY.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_COUNTRY.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_EMPLOYEETYPE.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_TELEPHONENUMBER.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_MOBILE.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_FACSIMILETELEPHONENUMBER.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_MANAGER.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_HOMEDRIVE.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_HOMEDIRECTORY.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_PROFILEPATH.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_SCRIPTPATH.equals(attribute)) {
            return true;
        } else if (DEFAULT_ATTRIBUTE_PASSWORD.equals(attribute)) {
            return true;
        }
        return false;
    }

    public void setAttributes(final UserIdentity user) {
        setAttributes(user.getAttributes());
    }
}
