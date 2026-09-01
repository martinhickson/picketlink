package org.picketlink.auth.oauth.store;

/** {@link IssuancePolicyStore} persisting the policy document in a {@link JsonDocumentStore}. */
public final class JdbcIssuancePolicyStore implements IssuancePolicyStore {

    public static final String DOCUMENT_ID = "policies";

    private final JsonDocumentStore documentStore;

    public JdbcIssuancePolicyStore(JsonDocumentStore documentStore) {
        this.documentStore = documentStore;
    }

    @Override
    public IssuancePolicyConfig load() {
        return IssuancePolicyConfig.fromJson(documentStore.load(DOCUMENT_ID));
    }

    @Override
    public void save(IssuancePolicyConfig config) {
        long version = documentStore.currentVersion(DOCUMENT_ID);
        documentStore.save(DOCUMENT_ID, config.toJson(), version);
    }
}
