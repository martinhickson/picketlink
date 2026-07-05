package org.picketlink.idm.admin.standalone;

import java.nio.file.Path;
import java.util.List;

public final class StandaloneConfigurationResult {

    private final WildFlyConfigurationProfile profile;
    private final Path standaloneXml;
    private final Path backupPath;
    private final boolean changed;
    private final int httpsListenersRemoved;
    private final List<String> messages;

    public StandaloneConfigurationResult(WildFlyConfigurationProfile profile, Path standaloneXml,
            Path backupPath, boolean changed, int httpsListenersRemoved, List<String> messages) {
        this.profile = profile;
        this.standaloneXml = standaloneXml;
        this.backupPath = backupPath;
        this.changed = changed;
        this.httpsListenersRemoved = httpsListenersRemoved;
        this.messages = List.copyOf(messages);
    }

    public WildFlyConfigurationProfile getProfile() {
        return profile;
    }

    public Path getStandaloneXml() {
        return standaloneXml;
    }

    public Path getBackupPath() {
        return backupPath;
    }

    public boolean isChanged() {
        return changed;
    }

    public int getHttpsListenersRemoved() {
        return httpsListenersRemoved;
    }

    public List<String> getMessages() {
        return messages;
    }

    public boolean isRestartRequired() {
        return changed || httpsListenersRemoved > 0;
    }

    public boolean isRequiresWildFlyModule() {
        return profile.isRequiresWildFlyModule();
    }

    public String getDeployerHandoffNote() {
        return "Provide the updated standalone.xml (backup: " + backupPath.getFileName()
                + ") to your deployer team so they can refresh the WildFly installation process. "
                + "A full WildFly restart is required before the Elytron changes take effect.";
    }
}
