/*
 * DefaultAttributeMapForMSAD class
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

import com.ricardolorenzo.identity.IdentityAttributeMap;
import com.ricardolorenzo.identity.user.UserIdentity;

/**
 * 
 * @author Ricardo Lorenzo
 * 
 */
public final class DefaultAttributeMapForMSAD extends IdentityAttributeMap {
    static {
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_UID, "sAMAccountName");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_CN, "cn");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_GIVENNAME, "givenname");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_SN, "sn");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_TITLE, "title");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_DISPLAYNAME, "displayname");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_DESCRIPTION, "description");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_COMPANY, "o");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_POSTALCODE, "postalcode");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_STREETADDRESS, "street");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_LOCALITY, "l");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_STATE, "st");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_EMPLOYEETYPE, "employeetype");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_TELEPHONENUMBER, "telephoneNumber");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_MOBILE, "mobile");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_FACSIMILETELEPHONENUMBER, "facsimileTelephoneNumber");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_HOMEDRIVE, "homeDrive");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_HOMEDIRECTORY, "homeDirectory");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_PROFILEPATH, "profilePath");
        setDefaultAttributeMap(UserIdentity.DEFAULT_ATTRIBUTE_SCRIPTPATH, "scriptPath");
    }
}
