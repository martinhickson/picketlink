package org.picketlink.auth.oauth.store;

/**
 * Loads and persists the {@link IssuancePolicyConfig} document. Default implementation is
 * {@link JdbcIssuancePolicyStore} (JSON in a CLOB via {@link JdbcClobDocumentStore});
 * {@link StaticIssuancePolicyStore} serves hard-coded defaults when no database is configured.
 */
public interface IssuancePolicyStore {

    IssuancePolicyConfig load();

    void save(IssuancePolicyConfig config);

    /** Non-persistent fallback returning the built-in defaults. */
    final class StaticIssuancePolicyStore implements IssuancePolicyStore {

        private volatile IssuancePolicyConfig config = new IssuancePolicyConfig();

        @Override
        public IssuancePolicyConfig load() {
            return config;
        }

        @Override
        public void save(IssuancePolicyConfig config) {
            this.config = config;
        }
    }
}
