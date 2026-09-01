package org.picketlink.auth.oauth.store;

import java.sql.Connection;
import java.sql.SQLException;

/** Opens JDBC connections for {@link JdbcClobDocumentStore}. */
public interface JdbcConnectionSource {

    Connection openConnection() throws SQLException;
}
