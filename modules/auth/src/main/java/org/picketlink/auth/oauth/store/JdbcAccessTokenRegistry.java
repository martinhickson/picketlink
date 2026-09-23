package org.picketlink.auth.oauth.store;

import org.picketlink.common.db.SqlDialect;
import org.picketlink.common.db.SqlDialects;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.picketlink.auth.oauth.json.OAuthJsonWriter;
import org.picketlink.auth.oauth.model.AccessTokenRecord;
import org.picketlink.auth.oauth.token.AccessTokenRegistry;

/**
 * JDBC {@link AccessTokenRegistry} so revocation and introspection survive restarts. Tokens are
 * keyed by the Base64url SHA-256 hash of the token value — raw JWTs are never persisted.
 * SQL is rendered through a {@link SqlDialect} (SQLite, PostgreSQL, Oracle), auto-detected
 * from the connection unless supplied explicitly.
 */
public final class JdbcAccessTokenRegistry implements AccessTokenRegistry {

    public static final String TABLE_NAME = "picketlink_auth_tokens";

    private final JdbcConnectionSource connectionSource;
    private volatile SqlDialect dialect;

    public JdbcAccessTokenRegistry(JdbcConnectionSource connectionSource) {
        this(connectionSource, null);
    }

    public JdbcAccessTokenRegistry(JdbcConnectionSource connectionSource, SqlDialect dialect) {
        this.connectionSource = connectionSource;
        this.dialect = dialect;
    }

    @Override
    public void store(AccessTokenRecord token) {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            connection.setAutoCommit(false);
            try {
                String tokenHash = hash(token.getTokenValue());
                int updated = update(connection, token, tokenHash);
                if (updated == 0) {
                    insert(connection, token, tokenHash);
                }
                connection.commit();
            } catch (SQLException ex) {
                connection.rollback();
                throw new IllegalStateException("Unable to store token record", ex);
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to store token record", ex);
        }
    }

    private static void insert(Connection connection, AccessTokenRecord token, String tokenHash)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO " + TABLE_NAME
                        + " (token_hash, client_id, scopes, issued_at, expires_at, subject_name)"
                        + " VALUES (?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, tokenHash);
            statement.setString(2, token.getClientId());
            statement.setString(3, String.join(" ", token.getScopes()));
            statement.setLong(4, token.getIssuedAt().toEpochMilli());
            statement.setLong(5, token.getExpiresAt().toEpochMilli());
            statement.setString(6, token.getSubject());
            statement.executeUpdate();
        }
    }

    private static int update(Connection connection, AccessTokenRecord token, String tokenHash)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "UPDATE " + TABLE_NAME
                        + " SET client_id = ?, scopes = ?, issued_at = ?, expires_at = ?, subject_name = ?"
                        + " WHERE token_hash = ?")) {
            statement.setString(1, token.getClientId());
            statement.setString(2, String.join(" ", token.getScopes()));
            statement.setLong(3, token.getIssuedAt().toEpochMilli());
            statement.setLong(4, token.getExpiresAt().toEpochMilli());
            statement.setString(5, token.getSubject());
            statement.setString(6, tokenHash);
            return statement.executeUpdate();
        }
    }

    @Override
    public Optional<AccessTokenRecord> findByTokenValue(String tokenValue) {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            return findByHash(connection, hash(tokenValue));
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to look up token record", ex);
        }
    }

    @Override
    public void revokeSubjectClient(String subject, String clientId) {
        if (subject == null || subject.isBlank() || clientId == null || clientId.isBlank()) {
            return;
        }
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM " + TABLE_NAME + " WHERE subject_name = ? AND client_id = ?")) {
                statement.setString(1, subject);
                statement.setString(2, clientId);
                statement.executeUpdate();
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to revoke token records", ex);
        }
    }

    @Override
    public void remove(String tokenValue) {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM " + TABLE_NAME + " WHERE token_hash = ?")) {
                statement.setString(1, hash(tokenValue));
                statement.executeUpdate();
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to remove token record", ex);
        }
    }

    /** Removes a token by its hash — used by the admin token browser which never sees raw tokens. */
    public boolean removeByTokenHash(String tokenHash) {
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM " + TABLE_NAME + " WHERE token_hash = ?")) {
                statement.setString(1, tokenHash);
                return statement.executeUpdate() > 0;
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to remove token record", ex);
        }
    }

    /** Lists token records for the admin token browser (hashes only, never raw tokens). */
    public List<TokenRecordView> list(int limit) {
        List<TokenRecordView> records = new ArrayList<>();
        try (Connection connection = connectionSource.openConnection()) {
            ensureSchema(connection);
            purgeExpired(connection);
            String select = "SELECT token_hash, client_id, scopes, issued_at, expires_at FROM "
                    + TABLE_NAME + " ORDER BY issued_at DESC";
            try (PreparedStatement statement = connection.prepareStatement(
                    dialect(connection).limitRows(select, Math.max(1, limit)))) {
                try (ResultSet rs = statement.executeQuery()) {
                    while (rs.next()) {
                        records.add(new TokenRecordView(rs.getString(1), rs.getString(2),
                                rs.getString(3), Instant.ofEpochMilli(rs.getLong(4)),
                                Instant.ofEpochMilli(rs.getLong(5))));
                    }
                }
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to list token records", ex);
        }
        return records;
    }

    private static Optional<AccessTokenRecord> findByHash(Connection connection, String tokenHash)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT client_id, scopes, issued_at, expires_at, subject_name FROM " + TABLE_NAME
                        + " WHERE token_hash = ?")) {
            statement.setString(1, tokenHash);
            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                String scopes = rs.getString(2);
                java.util.Set<String> scopeSet = new java.util.LinkedHashSet<>();
                if (scopes != null && !scopes.isBlank()) {
                    scopeSet.addAll(java.util.Arrays.asList(scopes.split(" ")));
                }
                return Optional.of(new AccessTokenRecord(
                        tokenHash,
                        rs.getString(1),
                        scopeSet,
                        Instant.ofEpochMilli(rs.getLong(3)),
                        Instant.ofEpochMilli(rs.getLong(4)),
                        rs.getString(5)));
            }
        }
    }

    private static void purgeExpired(Connection connection) throws SQLException {
            try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM " + TABLE_NAME + " WHERE expires_at < ?")) {
            statement.setLong(1, System.currentTimeMillis());
            statement.executeUpdate();
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
                        + "token_hash VARCHAR(64) PRIMARY KEY, "
                        + "client_id VARCHAR(128) NOT NULL, "
                        + "scopes VARCHAR(1024), "
                        + "issued_at BIGINT NOT NULL, "
                        + "expires_at BIGINT NOT NULL, "
                        + "subject_name VARCHAR(256))")) {
            statement.execute();
        }
        if (!columnExists(connection, "subject_name")) {
            try (PreparedStatement alter = connection.prepareStatement(
                    "ALTER TABLE " + TABLE_NAME + " ADD COLUMN subject_name VARCHAR(256)")) {
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

    private static String hash(String tokenValue) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(tokenValue.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    /** Admin-facing view of an issued token: hash (never the raw JWT), client, scopes, times. */
    public static final class TokenRecordView {

        private final String tokenHash;
        private final String clientId;
        private final String scopes;
        private final Instant issuedAt;
        private final Instant expiresAt;

        public TokenRecordView(String tokenHash, String clientId, String scopes,
                Instant issuedAt, Instant expiresAt) {
            this.tokenHash = tokenHash;
            this.clientId = clientId;
            this.scopes = scopes;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
        }

        public String getTokenHash() {
            return tokenHash;
        }

        public String getClientId() {
            return clientId;
        }

        public String getScopes() {
            return scopes;
        }

        public Instant getIssuedAt() {
            return issuedAt;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }

        public String toJson() {
            StringBuilder json = new StringBuilder();
            json.append('{');
            json.append("\"tokenHash\":\"").append(OAuthJsonWriter.escape(tokenHash)).append('"');
            json.append(",\"clientId\":\"").append(OAuthJsonWriter.escape(clientId)).append('"');
            json.append(",\"scopes\":\"").append(OAuthJsonWriter.escape(scopes == null ? "" : scopes))
                    .append('"');
            json.append(",\"issuedAt\":\"").append(issuedAt).append('"');
            json.append(",\"expiresAt\":\"").append(expiresAt).append('"');
            json.append('}');
            return json.toString();
        }
    }
}
