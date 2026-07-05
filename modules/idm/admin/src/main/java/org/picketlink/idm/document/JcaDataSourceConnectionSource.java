package org.picketlink.idm.document;

import java.sql.Connection;
import java.sql.SQLException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

/**
 * Enterprise JCA/JNDI {@link DataSource} lookup ({@code picketlink.idm.document.jdbc.connection=jca}, default).
 */
public final class JcaDataSourceConnectionSource implements IdmJdbcConnectionSource {

    private final DataSource dataSource;
    private final String jndiName;

    JcaDataSourceConnectionSource(String jndiName, DataSource dataSource) {
        this.jndiName = jndiName;
        this.dataSource = dataSource;
    }

    public static JcaDataSourceConnectionSource fromJndiName(String jndiName) {
        if (jndiName == null || jndiName.isBlank()) {
            throw new IllegalArgumentException("JNDI name is required for JCA JDBC connection mode");
        }
        return new JcaDataSourceConnectionSource(jndiName.trim(), lookupDataSource(jndiName.trim()));
    }

    String jndiName() {
        return jndiName;
    }

    @Override
    public Connection openConnection() throws SQLException {
        return dataSource.getConnection();
    }

    private static DataSource lookupDataSource(String jndiName) {
        try {
            Object resource = new InitialContext().lookup(jndiName);
            if (resource instanceof DataSource dataSource) {
                return dataSource;
            }
            throw new IllegalStateException("JNDI name " + jndiName + " is not a javax.sql.DataSource");
        } catch (NamingException ex) {
            throw new IllegalStateException("Unable to look up JCA data source at " + jndiName, ex);
        }
    }
}
