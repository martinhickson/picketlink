package org.picketlink.idm.document;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Classic JDBC URL connection source ({@code picketlink.idm.document.jdbc.connection=url}).
 */
public final class DriverManagerJdbcConnectionSource implements IdmJdbcConnectionSource {

    private final HibernateJdbcUrlInference.JdbcConnectionProperties connectionProperties;

    public DriverManagerJdbcConnectionSource(HibernateJdbcUrlInference.JdbcConnectionProperties connectionProperties) {
        this.connectionProperties = connectionProperties;
    }

    @Override
    public Connection openConnection() throws SQLException {
        if (connectionProperties.driverClassName() != null && !connectionProperties.driverClassName().isBlank()) {
            try {
                Class.forName(connectionProperties.driverClassName());
            } catch (ClassNotFoundException ex) {
                throw new SQLException("JDBC driver not found: " + connectionProperties.driverClassName(), ex);
            }
        }
        return DriverManager.getConnection(
                connectionProperties.url(),
                connectionProperties.user(),
                connectionProperties.password());
    }
}
