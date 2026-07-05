package org.picketlink.idm.realm.config;

import java.nio.file.Path;
import org.picketlink.common.config.PicketLinkSecurityConfigPaths;

public final class IdmRealmConfigStores {

    private static volatile IdmRealmConfigStore globalStore;

    private IdmRealmConfigStores() {
    }

    public static IdmRealmConfigStore globalStore() {
        IdmRealmConfigStore current = globalStore;
        if (current == null) {
            synchronized (IdmRealmConfigStores.class) {
                current = globalStore;
                if (current == null) {
                    current = new JsonFileIdmRealmConfigStore(PicketLinkSecurityConfigPaths.defaultRealmConfigFile());
                    globalStore = current;
                }
            }
        }
        return current;
    }

    public static void resetForTests() {
        globalStore = null;
        IdmRealmConfigService.resetForTests();
    }

    static Path defaultConfigFile() {
        return PicketLinkSecurityConfigPaths.defaultRealmConfigFile();
    }
}
