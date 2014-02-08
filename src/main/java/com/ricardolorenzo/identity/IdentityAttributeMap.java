/*
 * IdentityAttributeMap class
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
package com.ricardolorenzo.identity;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import com.ricardolorenzo.identity.user.UserIdentity;

/**
 * 
 * @author Ricardo Lorenzo
 * 
 */
public class IdentityAttributeMap {
    protected static Map<String, String> defaultAttributeMap;
    protected Map<String, String> attributeMap;

    static {
        defaultAttributeMap = new HashMap<String, String>();
    }

    public IdentityAttributeMap() {
        attributeMap = new HashMap<String, String>();
    }

    public IdentityAttributeMap(final Properties properties) {
        this();
        for (Entry<Object, Object> e : properties.entrySet()) {
            attributeMap.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
        }
    }

    public static Map<String, String> getDefaultReadMap() {
        return defaultAttributeMap;
    }

    public static Map<String, String> getDefaultWriteMap() {
        return reverse(defaultAttributeMap);
    }

    public Map<String, String> getReadMap() {
        return attributeMap;
    }

    public Map<String, String> getWriteMap() {
        return reverse(attributeMap);
    }

    private static <K, V> Map<V, K> reverse(final Map<K, V> map) {
        Map<V, K> rev = new HashMap<V, K>();
        for (Map.Entry<K, V> entry : map.entrySet()) {
            rev.put(entry.getValue(), entry.getKey());
        }
        return rev;
    }

    public void setAttributeMap(String attribute, String alternateAttribute) {
        if (attribute == null || attribute.isEmpty()) {
            return;
        } else if (alternateAttribute == null || alternateAttribute.isEmpty()) {
            return;
        }
        attributeMap.put(attribute, alternateAttribute);
    }

    protected static void setDefaultAttributeMap(String attribute, String alternateAttribute) {
        if (!UserIdentity.isDefaultAttribute(attribute)) {
            return;
        }
        if (alternateAttribute == null || alternateAttribute.isEmpty()) {
            return;
        }
        defaultAttributeMap.put(attribute, alternateAttribute);
    }
}
