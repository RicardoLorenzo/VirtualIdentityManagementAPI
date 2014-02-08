/*
 * Identity class
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

import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

/**
 * Represents an entry on directory
 * 
 * @author Ricardo Lorenzo
 * @version 0.1
 */
public abstract class Identity implements Serializable {
    private static final long serialVersionUID = -7782253102027043842L;

    public static final String getLastModifiedString(final Calendar date) {
        final Calendar c = Calendar.class.cast(date.clone());
        c.setTimeZone(TimeZone.getTimeZone("UTC"));
        final SimpleDateFormat sdf = new SimpleDateFormat("YYYYMMDDThhmmssZ");
        return sdf.format(c.getTime());
    }

    public static final Calendar parseLastModifiedString(final String date) throws IllegalArgumentException {
        final Calendar c = Calendar.getInstance();
        c.setTimeZone(TimeZone.getTimeZone("UTC"));
        final SimpleDateFormat sdf = new SimpleDateFormat("YYYYMMDDThhmmssZ");
        try {
            c.setTime(sdf.parse(date));
        } catch (final ParseException e) {
            throw new IllegalArgumentException("Cannot parse the date format, should be (YYYYMMDDThhmmssZ)");
        }
        return c;
    }

    private String ID;

    private final Map<String, Object[]> attributes = new HashMap<String, Object[]>();

    @Override
    public boolean equals(final Object o) {
        if (o == null) {
            return false;
        } else if (o instanceof Identity) {
            final Identity _entry = (Identity) o;
            return _entry.getID().equals(this.ID);
        }
        return false;
    }

    /**
     * Gets the value of an specific attribute. By default, any attribute can contain multiple
     * values, thats why you can get an array of objects here
     * 
     * @param name
     *            name of the attribute
     * @return Object[]
     */
    public Object[] getAttribute(final String name) {
        if (name == null) {
            return null;
        }
        return this.attributes.get(name.toLowerCase().trim());
    }

    /**
     * Gets the value of an specific attribute. By default, any attribute can contain multiple
     * values, but this method only retrieves the first value
     * 
     * @param name
     *            name of the attribute
     * @return Object[]
     */
    public String getAttributeFirstStringValue(final String name) {
        if (name == null) {
            return null;
        }
        if (hasAttribute(name)) {
            for (Object o : this.attributes.get(name)) {
                return String.valueOf(o);
            }
        }
        return null;
    }

    /**
     * Gets the value of an specific attribute. By default, any attribute can contain multiple
     * values, but this method only retrieves the first value
     * 
     * @param name
     *            name of the attribute
     * @return Object[]
     */
    public Object getAttributeFirstValue(final String name) {
        if (name == null) {
            return "";
        }
        if (hasAttribute(name)) {
            return this.attributes.get(name)[0];
        }
        return "";
    }

    /**
     * Get all the attribute names available in this entry instance
     * 
     * @return Set
     */
    public Set<String> getAttributeNames() {
        return this.attributes.keySet();
    }

    /**
     * Lest you get a complete <code>java.util.Map</code> with all attributes and values
     * 
     * @return Map
     */
    public Map<String, Object[]> getAttributes() {
        return this.attributes;
    }

    /**
     * Gets the ID of the entry
     * 
     * @return String
     */
    public String getID() {
        return this.ID;
    }

    /**
     * Lets you know if the actual entry instance contains an specific attribute
     * 
     * @param name
     *            Name of the attribute
     * @return boolean
     */
    public boolean hasAttribute(String name) {
        if (name == null) {
            return false;
        }
        name = name.toLowerCase().trim();
        return (this.attributes.containsKey(name) && (this.attributes.get(name) != null));
    }

    /**
     * Lets you know if the actual entry instance contains an specific attribute with an specific
     * value
     * 
     * @param name
     *            Name of the attribute
     * @param value
     *            The value of the attribute
     * @return boolean
     */
    public boolean hasAttributeValue(String name, final Object value) {
        if (name == null) {
            return false;
        }
        name = name.toLowerCase().trim();

        if (!this.attributes.containsKey(name)) {
            return false;
        }

        if (this.attributes.get(name) == null) {
            return false;
        }

        final List<Object> values = Arrays.asList(this.attributes.get(name));
        if (values.contains(value)) {
            return true;
        }
        return false;
    }

    /**
     * Removes an attribute
     * 
     * @param name
     *            Name of the attribute
     * 
     */
    public void removeAttribute(final String name) {
        if (name == null) {
            return;
        }
        this.attributes.remove(name.toLowerCase().trim());
    }

    /**
     * Sets a unique binary value of an attribute
     * 
     * @param name
     *            Name of the attribute
     * @param value
     *            byte[]
     */
    public void setAttribute(final String name, final byte[] value) {
        setAttribute(name, new Object[] { value });
    }

    /**
     * Sets the unique value of an attribute
     * 
     * @param name
     *            Name of the attribute
     * @param value
     *            Object
     */
    public void setAttribute(final String name, final Object value) {
        setAttribute(name, new Object[] { value });
    }

    /**
     * Sets the multiple values of an attribute
     * 
     * @param name
     *            Name of the attribute
     * @param value
     *            Object[]
     */
    public void setAttribute(final String name, final Object[] value) {
        if ((name == null) || (value == null)) {
            return;
        }
        this.attributes.put(name.toLowerCase().trim(), value);
    }

    /**
     * Loads the entire attribue map <code>java.util.Map</code>.
     * 
     * @param attributes
     *            An <code>java.util.Map</code>
     */
    protected void setAttributes(final Map<String, Object[]> attributes) {
        this.attributes.putAll(attributes);
    }

    /**
     * Sets the Distinguished name of the Entry
     * 
     * @param name
     *            Distinguished Name of the entry
     */
    public void setID(final String name) {
        this.ID = name;
    }

    @Override
    public String toString() {
        final StringBuilder _sb = new StringBuilder();
        _sb.append("EntryID: ");
        _sb.append(this.ID);
        _sb.append("\n");
        for (final String name : this.attributes.keySet()) {
            _sb.append(name);
            _sb.append(": ");
            if (this.attributes.get(name) != null) {
                int index = 0;
                for (final Object _o : this.attributes.get(name)) {
                    if (index > 0) {
                        _sb.append(",");
                    }
                    _sb.append(_o);
                    index++;
                }
            }
            _sb.append("\n");
        }
        return _sb.toString();
    }
}
