package org.picketlink.common.db;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Locale;

/** Registry of the supported {@link SqlDialect} implementations. */
public final class SqlDialects {

    /** SQLite: TEXT columns, LIMIT ? — the default embedded database for tests. */
    public static final SqlDialect SQLITE = new SqlDialect() {
        @Override
        public String textType() {
            return "TEXT";
        }

        @Override
        public String limitRows(String selectSql, int limit) {
            return selectSql + " LIMIT " + limit;
        }
    };

    /** PostgreSQL: TEXT columns, LIMIT ? — first-class production database. */
    public static final SqlDialect POSTGRES = new SqlDialect() {
        @Override
        public String textType() {
            return "TEXT";
        }

        @Override
        public String limitRows(String selectSql, int limit) {
            return selectSql + " LIMIT " + limit;
        }
    };

    /**
     * Oracle: CLOB columns, FETCH FIRST n ROWS ONLY. Supported at the dialect level;
     * verification is deferred until an Oracle environment is available (not OSS).
     */
    public static final SqlDialect ORACLE = new SqlDialect() {
        @Override
        public String textType() {
            return "CLOB";
        }

        @Override
        public String limitRows(String selectSql, int limit) {
            return selectSql + " FETCH FIRST " + limit + " ROWS ONLY";
        }
    };

    private SqlDialects() {
    }

    /** Auto-detects the dialect from the JDBC URL; defaults to PostgreSQL SQL. */
    public static SqlDialect forUrl(String url) {
        String normalized = url == null ? "" : url.toLowerCase(Locale.ROOT);
        if (normalized.contains("sqlite")) {
            return SQLITE;
        }
        if (normalized.contains("oracle")) {
            return ORACLE;
        }
        return POSTGRES;
    }

    /** Auto-detects the dialect from a live connection (product name). */
    public static SqlDialect forConnection(Connection connection) throws SQLException {
        String product = connection.getMetaData().getDatabaseProductName();
        if (product == null) {
            return POSTGRES;
        }
        String normalized = product.toLowerCase(Locale.ROOT);
        if (normalized.contains("sqlite")) {
            return SQLITE;
        }
        if (normalized.contains("oracle")) {
            return ORACLE;
        }
        return POSTGRES;
    }
}
