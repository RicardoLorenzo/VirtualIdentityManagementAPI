/*
 * DBConnectionManager class
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
package com.ricardolorenzo.db;

/**
 * 
 * Lets you create a new JDBC connection using the following parameters inside the properties
 * 
 * <ul>
 * <li>database.driver: Java class with the JDBC driver implementation</li>
 * <li>database.timezone: Database timezone</li>
 * <li>database.language: Database language</li>
 * <li>database.url: Database connection URL (depends on the driver)</li>
 * <li>database.user: Database user database.password: Database password</li>
 * </ul>
 * 
 * @author Ricardo Lorenzo
 * @version 0.1
 * 
 */
import java.sql.Driver;
import java.sql.DriverManager;
import java.util.Properties;
import java.util.TimeZone;

public class DBConnectionManager {
    private Properties configuration;

    public DBConnectionManager(Properties configuration) throws DBException {
        try {
            this.configuration = configuration;
            java.lang.reflect.Method getClassLoader = Thread.class.getMethod("getContextClassLoader", new Class[0]);
            ClassLoader contextClassLoader = (ClassLoader) getClassLoader.invoke(Thread.currentThread(), new Object[0]);
            DriverManager.registerDriver((Driver) contextClassLoader.loadClass(
                    configuration.getProperty("database.driver")).newInstance());
        } catch (Exception e) {
            throw new DBException(e.getMessage());
        }
    }

    /**
     * Returns an object <code>DBConnection</code> that represent an SQL connection
     * 
     * @return DBConnection
     */
    public DBConnection getConnection() {
        TimeZone tz = null;
        if (this.configuration.getProperty("database.timezone") != null) {
            tz = TimeZone.getTimeZone(this.configuration.getProperty("database.timezone"));
        }
        return new DBConnection(this.configuration.getProperty("database.url"),
                this.configuration.getProperty("database.user"), this.configuration.getProperty("database.password"),
                tz, this.configuration.getProperty("database.language"));
    }
}
