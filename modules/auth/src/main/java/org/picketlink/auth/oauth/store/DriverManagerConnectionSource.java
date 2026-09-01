package org.picketlink.auth.oauth.store;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/** Classic JDBC URL connection source ({@code picketlink.auth.jdbc.connection=url}). */
public final class DriverManagerConnectionSource implements JdbcConnectionSource {

    private final String url;
    private final String user;
    private final String password;
    private final String driverClassName;

    public DriverManagerConnectionSource(String url, String user, String password) {
        this(url, user, password, null);
    }

    public DriverManagerConnectionSource(String url, String user, String password, String driverClassName) {
        this.url = url;
        this.user = user;
        this.password = password;
        this.driverClassName = driverClassName;
    }

    @Override
    public Connection openConnection() throws SQLException {
        if (driverClassName != null && !driverClassName.isBlank()) {
            try {
                Class.forName(driverClassName);
            } catch (ClassNotFoundException ex) {
                throw new SQLException("JDBC driver not found: " + driverClassName, ex);
            }
        }
        if (user == null || user.isBlank()) {
            return DriverManager.getConnection(url);
        }
        return DriverManager.getConnection(url, user, password);
    }
}
