package org.picketlink.idm.realm.config;

import java.io.IOException;

public interface IdmRealmConfigStore {

    IdmRealmConfigDocument load() throws IOException;

    IdmRealmConfigDocument save(IdmRealmConfigDocument document) throws IOException;
}
