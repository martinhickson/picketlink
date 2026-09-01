package org.picketlink.idm.document;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * JDBC {@link IdmDocumentStore} storing the JSON envelope in {@code picketlink_idm.picketlink_idm_clob}.
 * Uses optimistic locking via the {@code version} column (same semantics as {@link JsonFileIdmDocumentStore}).
 * Not the default implementation; enable with {@code -Dpicketlink.idm.document.store=jdbc}.
 *
 * <p>JDBC connections use {@link IdmJdbcConnectionSources}:
 * JCA/JNDI ({@code connection=jca}, default) or classic JDBC URL ({@code connection=url}).
 */
public final class JdbcClobIdmDocumentStore implements IdmDocumentStore {

    public static final String TABLE_NAME = "picketlink_idm";
    public static final String CLOB_COLUMN = "picketlink_idm_clob";

    private final IdmJdbcConnectionSource connectionSource;
    private volatile org.picketlink.common.db.SqlDialect dialect;

    public JdbcClobIdmDocumentStore(IdmJdbcConnectionSource connectionSource) {
        this.connectionSource = connectionSource;
    }

    @Override
    public IdmRealmDocument load(String documentId) throws IOException {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT " + CLOB_COLUMN + ", version FROM " + TABLE_NAME + " WHERE document_id = ?")) {
                statement.setString(1, documentId);
                try (ResultSet rs = statement.executeQuery()) {
                    if (!rs.next()) {
                        return IdmRealmDocument.empty(documentId);
                    }
                    String json = rs.getString(CLOB_COLUMN);
                    return IdmDocumentJsonCodec.read(documentId, json);
                }
            }
        } catch (SQLException ex) {
            throw new IOException("Unable to load IDM document " + documentId, ex);
        }
    }

    @Override
    public IdmRealmDocument save(IdmRealmDocument document, long expectedVersion) throws IOException {
        if (document.getVersion() != expectedVersion + 1L) {
            throw new IllegalArgumentException("Saved document version must be expectedVersion + 1");
        }
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            connection.setAutoCommit(false);
            try {
                if (expectedVersion == 0L) {
                    insertDocument(connection, document);
                } else {
                    int updated = updateDocument(connection, document, expectedVersion);
                    if (updated == 0) {
                        long actual = readVersion(connection, document.getDocumentId());
                        throw new OptimisticLockException(document.getDocumentId(), expectedVersion, actual);
                    }
                }
                connection.commit();
                return document;
            } catch (RuntimeException ex) {
                connection.rollback();
                throw ex;
            } catch (SQLException ex) {
                connection.rollback();
                throw new IOException("Unable to save IDM document " + document.getDocumentId(), ex);
            }
        } catch (SQLException ex) {
            throw new IOException("Unable to save IDM document " + document.getDocumentId(), ex);
        }
    }

    private org.picketlink.common.db.SqlDialect dialect(Connection connection) throws SQLException {
        org.picketlink.common.db.SqlDialect current = dialect;
        if (current == null) {
            current = org.picketlink.common.db.SqlDialects.forConnection(connection);
            dialect = current;
        }
        return current;
    }

    private void ensureSchema(Connection connection) throws SQLException {
        String textType = dialect(connection).textType();
        try (PreparedStatement statement = connection.prepareStatement(
                "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
                        + "document_id VARCHAR(128) PRIMARY KEY, "
                        + CLOB_COLUMN + " " + textType + " NOT NULL, "
                        + "version BIGINT NOT NULL, "
                        + "updated_at BIGINT NOT NULL)")) {
            statement.execute();
        }
    }

    private static void insertDocument(Connection connection, IdmRealmDocument document) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO " + TABLE_NAME + " (document_id, " + CLOB_COLUMN + ", version, updated_at) VALUES (?, ?, ?, ?)")) {
            statement.setString(1, document.getDocumentId());
            statement.setString(2, IdmDocumentJsonCodec.write(document));
            statement.setLong(3, document.getVersion());
            statement.setLong(4, System.currentTimeMillis());
            statement.executeUpdate();
        }
    }

    private static int updateDocument(Connection connection, IdmRealmDocument document, long expectedVersion)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "UPDATE " + TABLE_NAME + " SET " + CLOB_COLUMN + " = ?, version = ?, updated_at = ? "
                        + "WHERE document_id = ? AND version = ?")) {
            statement.setString(1, IdmDocumentJsonCodec.write(document));
            statement.setLong(2, document.getVersion());
            statement.setLong(3, System.currentTimeMillis());
            statement.setString(4, document.getDocumentId());
            statement.setLong(5, expectedVersion);
            return statement.executeUpdate();
        }
    }

    private static long readVersion(Connection connection, String documentId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT version FROM " + TABLE_NAME + " WHERE document_id = ?")) {
            statement.setString(1, documentId);
            try (ResultSet rs = statement.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        }
        return 0L;
    }
}
