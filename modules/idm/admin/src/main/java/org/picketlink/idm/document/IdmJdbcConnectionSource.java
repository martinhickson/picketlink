package org.picketlink.idm.document;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Opens JDBC connections for {@link JdbcClobIdmDocumentStore}.
 */
public interface IdmJdbcConnectionSource {

    Connection openConnection() throws SQLException;
}
