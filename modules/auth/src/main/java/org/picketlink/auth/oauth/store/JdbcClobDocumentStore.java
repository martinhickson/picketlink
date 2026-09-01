package org.picketlink.auth.oauth.store;

import org.picketlink.common.db.SqlDialect;
import org.picketlink.common.db.SqlDialects;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * {@link JsonDocumentStore} storing each JSON document in a large text column of
 * {@code picketlink_auth}, with optimistic locking via the {@code version} column — the same
 * semantics as the IDM {@code JdbcClobIdmDocumentStore}. Enabled with
 * {@code -Dpicketlink.auth.store=jdbc}. SQL is rendered through a {@link SqlDialect}
 * (SQLite, PostgreSQL, Oracle); the dialect is auto-detected from the connection unless
 * supplied explicitly.
 */
public final class JdbcClobDocumentStore implements JsonDocumentStore {

    public static final String TABLE_NAME = "picketlink_auth";
    public static final String CLOB_COLUMN = "document_json";

    private final JdbcConnectionSource connectionSource;
    private volatile SqlDialect dialect;

    public JdbcClobDocumentStore(JdbcConnectionSource connectionSource) {
        this(connectionSource, null);
    }

    public JdbcClobDocumentStore(JdbcConnectionSource connectionSource, SqlDialect dialect) {
        this.connectionSource = connectionSource;
        this.dialect = dialect;
    }

    @Override
    public String load(String documentId) {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT " + CLOB_COLUMN + " FROM " + TABLE_NAME + " WHERE document_id = ?")) {
                statement.setString(1, documentId);
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next() ? rs.getString(CLOB_COLUMN) : null;
                }
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to load document " + documentId, ex);
        }
    }

    @Override
    public long currentVersion(String documentId) {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            return readVersion(connection, documentId);
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to read version of " + documentId, ex);
        }
    }

    @Override
    public long save(String documentId, String json, long expectedVersion) {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            connection.setAutoCommit(false);
            try {
                long newVersion = expectedVersion + 1L;
                if (expectedVersion == 0L) {
                    insert(connection, documentId, json, newVersion);
                } else {
                    int updated = update(connection, documentId, json, expectedVersion, newVersion);
                    if (updated == 0) {
                        long actual = readVersion(connection, documentId);
                        throw new DocumentConcurrentUpdateException(documentId, expectedVersion, actual);
                    }
                }
                connection.commit();
                return newVersion;
            } catch (RuntimeException ex) {
                connection.rollback();
                throw ex;
            } catch (SQLException ex) {
                connection.rollback();
                throw new IllegalStateException("Unable to save document " + documentId, ex);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to save document " + documentId, ex);
        }
    }

    private SqlDialect dialect(Connection connection) throws SQLException {
        SqlDialect current = dialect;
        if (current == null) {
            current = SqlDialects.forConnection(connection);
            dialect = current;
        }
        return current;
    }

    private void ensureSchema(Connection connection) throws SQLException {
        SqlDialect sqlDialect = dialect(connection);
        try (PreparedStatement statement = connection.prepareStatement(
                "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
                        + "document_id VARCHAR(128) PRIMARY KEY, "
                        + CLOB_COLUMN + " " + sqlDialect.textType() + " NOT NULL, "
                        + "version BIGINT NOT NULL, "
                        + "updated_at BIGINT NOT NULL)")) {
            statement.execute();
        }
    }

    private static void insert(Connection connection, String documentId, String json, long version)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO " + TABLE_NAME + " (document_id, " + CLOB_COLUMN + ", version, updated_at)"
                        + " VALUES (?, ?, ?, ?)")) {
            statement.setString(1, documentId);
            statement.setString(2, json);
            statement.setLong(3, version);
            statement.setLong(4, System.currentTimeMillis());
            statement.executeUpdate();
        }
    }

    private static int update(Connection connection, String documentId, String json,
            long expectedVersion, long newVersion) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "UPDATE " + TABLE_NAME + " SET " + CLOB_COLUMN + " = ?, version = ?, updated_at = ?"
                        + " WHERE document_id = ? AND version = ?")) {
            statement.setString(1, json);
            statement.setLong(2, newVersion);
            statement.setLong(3, System.currentTimeMillis());
            statement.setString(4, documentId);
            statement.setLong(5, expectedVersion);
            return statement.executeUpdate();
        }
    }

    private static long readVersion(Connection connection, String documentId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT version FROM " + TABLE_NAME + " WHERE document_id = ?")) {
            statement.setString(1, documentId);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next() ? rs.getLong(1) : 0L;
            }
        }
    }
}
