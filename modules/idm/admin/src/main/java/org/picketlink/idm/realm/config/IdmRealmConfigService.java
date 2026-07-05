package org.picketlink.idm.realm.config;

import java.io.IOException;
import org.picketlink.idm.realm.IdmRealmBackends;
import org.picketlink.idm.realm.IdmRealmProviderConfig;

public final class IdmRealmConfigService {

    private static volatile IdmRealmConfigService globalService;

    private final IdmRealmConfigStore store;
    private volatile IdmRealmConfigDocument cached;

    public IdmRealmConfigService(IdmRealmConfigStore store) {
        this.store = store;
    }

    public static IdmRealmConfigService global() {
        IdmRealmConfigService current = globalService;
        if (current == null) {
            synchronized (IdmRealmConfigService.class) {
                current = globalService;
                if (current == null) {
                    current = new IdmRealmConfigService(IdmRealmConfigStores.globalStore());
                    globalService = current;
                }
            }
        }
        return current;
    }

    public static void resetForTests() {
        globalService = null;
    }

    public IdmRealmConfigDocument current() throws IOException {
        IdmRealmConfigDocument document = cached;
        if (document == null) {
            synchronized (this) {
                document = cached;
                if (document == null) {
                    document = store.load();
                    cached = document;
                }
            }
        }
        return document;
    }

    public IdmRealmConfigSnapshot loadSnapshot() throws IOException {
        IdmRealmConfigDocument document = current();
        return new IdmRealmConfigSnapshot(
                document,
                configFilePath(),
                IdmRealmProviderConfig.resolveDefaultScimBaseUrl(document.getScimContextPath()),
                IdmRealmProviderConfig.resolveEffectiveScimBaseUrl(document));
    }

    public IdmRealmConfigSnapshot save(IdmRealmConfigDocument document) throws IOException {
        store.save(document);
        cached = document;
        IdmRealmBackends.resetForTests();
        return loadSnapshot();
    }

    private String configFilePath() {
        if (store instanceof JsonFileIdmRealmConfigStore jsonStore) {
            return jsonStore.getConfigFile().toString();
        }
        return IdmRealmConfigStores.defaultConfigFile().toString();
    }
}
