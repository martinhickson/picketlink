package org.picketlink.common.db;

/**
 * SQL dialect abstraction for the JSON-in-CLOB stores. The JDBC layer must work across the
 * supported matrix — SQLite and PostgreSQL first-class, Oracle supported at the dialect level
 * (verification deferred). Obtain an instance via {@link SqlDialects#forUrl(String)} or
 * {@link SqlDialects#forConnection(java.sql.Connection)}.
 */
public interface SqlDialect {

    /** Large text column type for JSON documents (CLOB or TEXT depending on the engine). */
    String textType();

    /**
     * Row-limited select for the token browser, parameterized as needed by the engine
     * (e.g. {@code LIMIT ?} on SQLite/PostgreSQL, {@code FETCH FIRST ? ROWS ONLY} on Oracle).
     */
    String limitRows(String selectSql, int limit);
}
