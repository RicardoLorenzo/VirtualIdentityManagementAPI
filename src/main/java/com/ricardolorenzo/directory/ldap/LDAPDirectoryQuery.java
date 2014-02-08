/*
 * LDAPDirectoryEntry class
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
package com.ricardolorenzo.directory.ldap;

/**
 * DirectoryQuery
 * 
 * @author Ricardo Lorenzo
 * @version 0.1
 */
import java.util.ArrayList;
import java.util.List;

public class LDAPDirectoryQuery {
    public static final int AND = 101;
    public static final int OR = 102;
    public static final int EXACT = 0;
    public static final int STARTS_WITH = 1;
    public static final int ENDS_WITH = 2;
    public static final int CONTAINS = 3;
    public static final int NOT_EXACT = 4;
    public static final int NOT_CONTAINS = 5;
    public static final int BRANCH = 6;
    public static final int APPROXIMATE = 7;
    public static final int GREATER = 8;
    public static final int LOWER = 9;
    private int type;
    private List<Object> conditions;
    private int offset;

    /**
     * Instance a new <code>DirectoryQuery</code> object
     */
    public LDAPDirectoryQuery() {
        this.conditions = new ArrayList<Object>();
        this.offset = 0;
        this.type = AND;
    }

    /**
     * Instance a new <code>DirectoryQuery</code> object
     */
    public LDAPDirectoryQuery(int type) throws Exception {
        this.conditions = new ArrayList<Object>();
        this.offset = 0;
        if (type != AND && type != OR) {
            throw new Exception("type must be 101 (AND) or 102 (OR)");
        }
        this.type = type;
    }

    /**
     * Add new condition to the query, key refers to the name of the attribute and value refers to
     * the match value
     * 
     * @param key
     *            String
     * @param value
     *            Object
     */
    public void addCondition(String key, Object value) {
        this.conditions.add(new Object[] { new Integer(0), key, value });
    }

    /**
     * Adds a complete query to conditions
     * 
     * @param LDAPDirectoryQuery
     */
    public void addCondition(LDAPDirectoryQuery q) {
        this.conditions.add(q);
    }

    /**
     * Add new condition to the query, key refers to the name of the attribute and value refers to
     * the match value. By default condition type is EXACT, but you can use also STARTS_WITH,
     * CONTAINS and ENDS_WITH
     * 
     * @param key
     *            String
     * @param value
     *            Object
     * @param type
     *            int
     */
    public void addCondition(String key, Object value, int type) {
        this.conditions.add(new Object[] { new Integer(type), key, value });
    }

    /**
     * Si se utiliza un bucle para extraer las condiciones, este m&eacute;todo indica se existen
     * m&aacute;s condiciones por extraer.
     * 
     * @return boolean
     */
    public boolean hasMoreConditions() {
        if (this.offset < this.conditions.size()) {
            return true;
        }
        return false;
    }

    /**
     * Returns an object <code>java.lang.Object[]</code> with the values of
     * 
     * @return Object
     */
    public Object nextCondition() {
        Object _condition = this.conditions.get(this.offset);
        this.offset++;
        return _condition;
    }

    /**
     * Returns the total number of conditions, without taken care about BRANCH conditions
     * 
     * @return int
     */
    public int totalConditions() {
        int k = 0;
        for (int i = this.conditions.size(); --i >= 0;) {
            if (this.conditions.get(i) instanceof Object[]) {
                if (((Object[]) this.conditions.get(i))[0].equals(new Integer(BRANCH))) {
                    --k;
                }
            }
        }
        return this.conditions.size() + k;
    }

    /**
     * Returns type of query (for example OR or AND)
     * 
     * @return int
     */
    public int getType() {
        return this.type;
    }
}