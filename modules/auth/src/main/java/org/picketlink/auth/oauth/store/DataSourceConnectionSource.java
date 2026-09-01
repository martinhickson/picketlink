package org.picketlink.auth.oauth.store;

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

/** Container-managed connection source (JNDI {@code DataSource}). */
public final class DataSourceConnectionSource implements JdbcConnectionSource {

    private final DataSource dataSource;

    public DataSourceConnectionSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public Connection openConnection() throws SQLException {
        return dataSource.getConnection();
    }
}
