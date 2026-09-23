package org.picketlink.oidc.provider;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.picketlink.auth.oauth.store.JdbcConnectionSource;

/**
 * JDBC {@link RefreshTokenStore} so refresh rotation and replay detection survive restarts.
 * Raw token values are never stored — only SHA-256 hashes. Uses portable SQL (portable types,
 * update-then-insert upserts) across the dialect matrix (SQLite/PostgreSQL/Oracle); the
 * retired-hash bookkeeping is expressed with a {@code retired} flag on the same table.
 */
public final class JdbcRefreshTokenStore implements RefreshTokenStore {

    public static final String TABLE_NAME = "picketlink_oidc_refresh";

    private final JdbcConnectionSource connectionSource;

    public JdbcRefreshTokenStore(JdbcConnectionSource connectionSource) {
        this.connectionSource = connectionSource;
    }

    @Override
    public void save(RefreshTokenRecord record) {
        withConnection(connection -> {
            upsert(connection, record, false);
        });
    }

    @Override
    public RefreshTokenRecord find(String tokenHash) {
        return read(tokenHash, false);
    }

    @Override
    public RefreshTokenRecord remove(String tokenHash) {
        RefreshTokenRecord record = read(tokenHash, false);
        if (record != null) {
            withConnection(connection -> {
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM " + TABLE_NAME + " WHERE token_hash = ? AND retired = 0")) {
                    statement.setString(1, tokenHash);
                    statement.executeUpdate();
                }
            });
        }
        return record;
    }

    @Override
    public void rememberRetired(String tokenHash, String family) {
        withConnection(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE " + TABLE_NAME + " SET retired = 1 WHERE token_hash = ?")) {
                statement.setString(1, tokenHash);
                int updated = statement.executeUpdate();
                if (updated == 0) {
                    // the live row was already removed; keep the family mapping for replay detection
                    try (PreparedStatement insert = connection.prepareStatement(
                            "INSERT INTO " + TABLE_NAME + " (token_hash, client_id, subject_name,"
                                    + " scopes, nonce, family_id, expires_at, retired)"
                                    + " VALUES (?, '', '', '', '', ?, 0, 1)")) {
                        insert.setString(1, tokenHash);
                        insert.setString(2, family);
                        insert.executeUpdate();
                    }
                }
            }
        });
    }

    @Override
    public String retiredFamily(String tokenHash) {
        return readFamilyWhereRetired(tokenHash, true);
    }

    @Override
    public void revokeFamily(String family) {
        withConnection(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM " + TABLE_NAME + " WHERE family_id = ?")) {
                statement.setString(1, family);
                statement.executeUpdate();
            }
        });
    }

    @Override
    public void revokeSubjectClient(String subject, String clientId) {
        if (subject == null || clientId == null) {
            return;
        }
        withConnection(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM " + TABLE_NAME
                            + " WHERE subject_name = ? AND client_id = ? AND retired = 0")) {
                statement.setString(1, subject);
                statement.setString(2, clientId);
                statement.executeUpdate();
            }
        });
    }

    private RefreshTokenRecord read(String tokenHash, boolean retired) {
        final RefreshTokenRecord[] result = new RefreshTokenRecord[1];
        withConnection(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT client_id, subject_name, scopes, nonce, family_id, expires_at, dpop_jkt FROM "
                            + TABLE_NAME + " WHERE token_hash = ? AND retired = ?")) {
                statement.setString(1, tokenHash);
                statement.setInt(2, retired ? 1 : 0);
                try (ResultSet rs = statement.executeQuery()) {
                    if (rs.next()) {
                        result[0] = new RefreshTokenRecord(tokenHash, rs.getString(1),
                                rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5),
                                rs.getLong(6), rs.getString(7));
                    }
                }
            }
        });
        return result[0];
    }

    private String readFamilyWhereRetired(String tokenHash, boolean retired) {
        final String[] family = new String[1];
        withConnection(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT family_id FROM " + TABLE_NAME + " WHERE token_hash = ? AND retired = ?")) {
                statement.setString(1, tokenHash);
                statement.setInt(2, retired ? 1 : 0);
                try (ResultSet rs = statement.executeQuery()) {
                    if (rs.next()) {
                        family[0] = rs.getString(1);
                    }
                }
            }
        });
        return family[0];
    }

    private static void upsert(Connection connection, RefreshTokenRecord record, boolean retired)
            throws SQLException {
        int updated = update(connection, record, retired);
        if (updated == 0) {
            insert(connection, record, retired);
        }
    }

    private static int update(Connection connection, RefreshTokenRecord record, boolean retired)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "UPDATE " + TABLE_NAME + " SET client_id = ?, subject_name = ?, scopes = ?,"
                        + " nonce = ?, family_id = ?, expires_at = ?, dpop_jkt = ? WHERE token_hash = ?")) {
            statement.setString(1, record.getClientId());
            statement.setString(2, record.getSubject());
            statement.setString(3, record.getScopes());
            statement.setString(4, record.getNonce());
            statement.setString(5, record.getFamily());
            statement.setLong(6, record.getExpiresAtEpochSeconds());
            statement.setString(7, record.getDpopJkt());
            statement.setString(8, record.getTokenHash());
            return statement.executeUpdate();
        }
    }

    private static void insert(Connection connection, RefreshTokenRecord record, boolean retired)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO " + TABLE_NAME + " (token_hash, client_id, subject_name, scopes,"
                        + " nonce, family_id, expires_at, retired, dpop_jkt)"
                        + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, record.getTokenHash());
            statement.setString(2, record.getClientId());
            statement.setString(3, record.getSubject());
            statement.setString(4, record.getScopes());
            statement.setString(5, record.getNonce());
            statement.setString(6, record.getFamily());
            statement.setLong(7, record.getExpiresAtEpochSeconds());
            statement.setInt(8, retired ? 1 : 0);
            statement.setString(9, record.getDpopJkt());
            statement.executeUpdate();
        }
    }

    private void withConnection(SqlWork work) {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            work.run(connection);
        } catch (SQLException ex) {
            throw new IllegalStateException("Refresh token store failure", ex);
        }
    }

    private void ensureSchema(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
                        + "token_hash VARCHAR(64) PRIMARY KEY, "
                        + "client_id VARCHAR(128) NOT NULL, "
                        + "subject_name VARCHAR(256), "
                        + "scopes VARCHAR(1024), "
                        + "nonce VARCHAR(256), "
                        + "family_id VARCHAR(64) NOT NULL, "
                        + "expires_at BIGINT NOT NULL, "
                        + "retired INTEGER NOT NULL DEFAULT 0, "
                        + "dpop_jkt VARCHAR(256))")) {
            statement.execute();
        }
        if (!columnExists(connection, "dpop_jkt")) {
            try (PreparedStatement alter = connection.prepareStatement(
                    "ALTER TABLE " + TABLE_NAME + " ADD COLUMN dpop_jkt VARCHAR(256)")) {
                alter.execute();
            }
        }
    }

    private static boolean columnExists(Connection connection, String column) throws SQLException {
        DatabaseMetaData meta = connection.getMetaData();
        if (findColumn(meta, TABLE_NAME, column)) {
            return true;
        }
        return findColumn(meta, TABLE_NAME.toUpperCase(), column.toUpperCase());
    }

    private static boolean findColumn(DatabaseMetaData meta, String table, String column)
            throws SQLException {
        try (ResultSet columns = meta.getColumns(null, null, table, column)) {
            return columns.next();
        }
    }

    private interface SqlWork {

        void run(Connection connection) throws SQLException;
    }
}
