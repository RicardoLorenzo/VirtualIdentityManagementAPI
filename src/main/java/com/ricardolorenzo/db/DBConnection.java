/*
 * DBConnection class
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
 * @author Ricardo Lorenzo
 * @version 0.1
 * 
 */
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

public class DBConnection {
    private final List<Object> objects;
    private final String url;
    private final String user;
    private final String password;
    private java.sql.Connection connection;
    private TimeZone tz;
    private String language;

    protected DBConnection(final String url, final String user, final String password, final TimeZone tz,
            final String language) {
        this.url = url;
        this.user = user;
        this.password = password;
        this.objects = new ArrayList<Object>();
        if (tz == null) {
            this.tz = TimeZone.getDefault();
        } else {
            this.tz = tz;
        }
        if ((language == null) || language.isEmpty()) {
            this.language = Locale.getDefault().getLanguage();
        } else {
            this.language = language;
        }
    }

    private static final Object getObject(final Object o) {
        try {
            if (Number.class.isAssignableFrom(o.getClass())) {
                return getObjectInstance(o, Number.class).doubleValue();
            } else if (Timestamp.class.isAssignableFrom(o.getClass())) {
                return getObjectInstance(o, Timestamp.class);
            } else if (Date.class.isAssignableFrom(o.getClass())) {
                return getObjectInstance(o, Date.class);
            } else if (java.util.Date.class.isAssignableFrom(o.getClass())) {
                return new Timestamp(getObjectInstance(o, java.util.Date.class).getTime());
            } else if (java.util.Calendar.class.isAssignableFrom(o.getClass())) {
                return new Timestamp(getObjectInstance(o, java.util.Calendar.class).getTimeInMillis());
            } else {
                return o;
            }
        } catch (final ClassCastException e) {
            // nothing
        }
        return null;
    }

    private static final <T> T getObjectInstance(final Object o, final Class<T> objectClass) {
        try {
            if (Number.class.isAssignableFrom(o.getClass())) {
                return objectClass.cast(o);
            }
        } catch (final ClassCastException e) {
            // nothing
        }
        return null;
    }

    /**
     * Clears the objects on the query
     */
    public void clearObjects() {
        this.objects.clear();
    }

    private List<Map<String, Object>> internal_query(final PreparedStatement ps) throws SQLException {
        final List<Map<String, Object>> results = new ArrayList<Map<String, Object>>();

        setDateTimeValue(ps);
        ResultSet rs = null;
        if (ps.execute()) {
            rs = ps.getResultSet();
        }
        if (rs != null) {
            final List<String> columns = new ArrayList<String>();
            /*
             * Get the column names
             */
            final ResultSetMetaData rsmd = rs.getMetaData();
            for (int i = rsmd.getColumnCount(); --i >= 0;) {
                columns.add(rsmd.getColumnName(i + 1));
            }
            while (rs.next()) {
                final Map<String, Object> row = new HashMap<String, Object>();
                for (final String columnName : columns) {
                    row.put(columnName, getObject(rs.getObject(columnName)));
                }
                results.add(row);
            }
            rs.close();
        }
        return results;
    }

    /**
     * Execute a query on the RDBMS and return a <code>java.util.List</code> with a
     * <code>java.util.HashMap</code> with the column values per row.
     * 
     * @param query
     *            String
     * @return ArrayList
     * @exception DBException
     */
    public List<Map<String, Object>> query(final String query) throws DBException {
        PreparedStatement ps = null;
        try {
            if ((this.connection != null) && !this.connection.isClosed()) {
                throw new DBException("active transaction is on the way");
            }
        } catch (final SQLException e) {
            throw new DBException(e.getMessage());
        }
        try {
            if ((this.url != null) && this.url.contains("jdbc:as400:")) {
                this.connection.setTransactionIsolation(Connection.TRANSACTION_NONE);
            }
            this.connection = DriverManager.getConnection(this.url, this.user, this.password);
            ps = this.connection.prepareStatement(query);
            return internal_query(ps);
        } catch (final SQLException e) {
            throw new DBException(e.getMessage());
        } finally {
            this.objects.clear();
            try {
                if (ps != null) {
                    ps.close();
                }
                if (this.connection != null) {
                    this.connection.close();
                }
            } catch (final SQLException e) {
                throw new DBException(e.getMessage());
            }
        }
    }

    private void setDateTimeValue(final PreparedStatement ps) throws SQLException {
        int index = 0;
        for (final Object o : this.objects) {
            if (o instanceof Timestamp) {
                ps.setTimestamp(index, getObjectInstance(o, Timestamp.class));
            } else if (o instanceof Date) {
                ps.setDate(index, getObjectInstance(o, Date.class));
            } else if (o instanceof java.util.Date) {
                ps.setTimestamp(index, new Timestamp(getObjectInstance(o, java.util.Date.class).getTime()));
            } else if (o instanceof java.util.Calendar) {
                ps.setTimestamp(index, new Timestamp(getObjectInstance(o, java.util.Calendar.class).getTimeInMillis()));
            } else {
                ps.setObject(index, o);
            }
            index++;
        }
    }

    /**
     * Define los objetos que hacen parte de una consulta como <code>java.util.Date</code> y los
     * ubica en la piscion de cada caracter "?" dentro de la cadena de la consulta.
     * 
     * @param index
     *            int
     * @param object
     *            Object
     * @exception DBException
     */
    public void setObject(final int index, final Object object) throws DBException {
        if (index < 0) {
            throw new DBException("index out of range (must be >= 0)");
        }
        this.objects.add(index, object);
    }

    /**
     * Closes an active transaction.
     * 
     * @exception DBException
     */
    public void transactionClose() throws DBException {
        try {
            if (this.connection != null) {
                this.connection.commit();
                this.connection.close();
            }
        } catch (final SQLException e) {
            throw new DBException(e.getMessage());
        }
    }

    /**
     * Let you perform a COMMIT on active transaction.
     * 
     * @exception DBException
     */
    public void transactionCommit() throws DBException {
        try {
            if ((this.connection == null) || this.connection.isClosed()) {
                throw new DBException("cannot find an active transaction");
            }
            if (this.connection != null) {
                this.connection.commit();
            }
        } catch (final SQLException e) {
            throw new DBException(e.getMessage());
        }
    }

    /**
     * Inicia una transaccion SQL.
     * 
     * @exception DBException
     */
    public void transactionInit() throws DBException {
        try {
            System.setProperty("user.country", this.language);
            System.setProperty("user.language", this.language);
            TimeZone.setDefault(this.tz);
            this.connection = DriverManager.getConnection(this.url, this.user, this.password);
            this.connection.setAutoCommit(false);
            if ((this.url != null) && this.url.contains("jdbc:as400:")) {
                this.connection.setTransactionIsolation(Connection.TRANSACTION_NONE);
            }
        } catch (final SQLException e) {
            throw new DBException(e.getMessage());
        }
    }

    /**
     * Execute a query on the RDBMS on an active transaction and return a
     * <code>java.util.List</code> with a <code>java.util.HashMap</code> with the column values per
     * row.
     * 
     * @param query
     *            String
     * @return ArrayList
     * @exception DBException
     */
    public List<Map<String, Object>> transactionQuery(final String query) throws DBException {
        java.sql.PreparedStatement ps = null;
        try {
            if (this.connection.isClosed()) {
                throw new DBException("cannot find an active transaction");
            }
            ps = this.connection.prepareStatement(query);
            return internal_query(ps);
        } catch (final SQLException e) {
            throw new DBException(e.getMessage());
        } finally {
            this.objects.clear();
            try {
                if (ps != null) {
                    ps.close();
                }
            } catch (final SQLException e) {
                throw new DBException(e.getMessage());
            }
        }
    }

    /**
     * Let you perform a ROLLBACK on active transaction.
     * 
     * @exception DBException
     */
    public void transactionRollback() throws DBException {
        try {
            if (this.connection == null) {
                throw new DBException("cannot establish the connection.");
            }
            if (this.connection.isClosed()) {
                throw new DBException("cannot find an active transaction");
            }
            if (this.connection != null) {
                this.connection.rollback();
            }
        } catch (final SQLException e) {
            throw new DBException(e.getMessage());
        }
    }
}
