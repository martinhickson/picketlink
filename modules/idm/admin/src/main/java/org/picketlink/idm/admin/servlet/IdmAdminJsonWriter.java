package org.picketlink.idm.admin.servlet;

import java.util.List;
import org.picketlink.idm.admin.standalone.StandaloneConfigurationResult;
import org.picketlink.idm.admin.standalone.WildFlyConfigurationProfile;

public final class IdmAdminJsonWriter {

    private IdmAdminJsonWriter() {
    }

    public static String writeProfiles() {
        StringBuilder json = new StringBuilder();
        json.append('[');
        boolean first = true;
        for (WildFlyConfigurationProfile profile : WildFlyConfigurationProfile.all()) {
            if (!first) {
                json.append(',');
            }
            first = false;
            json.append('{');
            append(json, "id", profile.getId());
            append(json, "title", profile.getTitle());
            append(json, "description", profile.getDescription());
            append(json, "mutatesStandaloneXml", Boolean.toString(profile.isMutatesStandaloneXml()));
            append(json, "requiresWildFlyModule", Boolean.toString(profile.isRequiresWildFlyModule()));
            json.append('}');
        }
        json.append(']');
        return json.toString();
    }

    public static String writeResult(StandaloneConfigurationResult result) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        append(json, "profileId", result.getProfile().getId());
        append(json, "standaloneXml", result.getStandaloneXml().toString());
        append(json, "backupPath", result.getBackupPath().toString());
        append(json, "backupFile", result.getBackupPath().getFileName().toString());
        append(json, "changed", Boolean.toString(result.isChanged()));
        append(json, "restartRequired", Boolean.toString(result.isRestartRequired()));
        append(json, "httpsListenersRemoved", Integer.toString(result.getHttpsListenersRemoved()));
        append(json, "requiresWildFlyModule", Boolean.toString(result.isRequiresWildFlyModule()));
        append(json, "deployerHandoffNote", result.getDeployerHandoffNote());
        json.append("\"messages\":[");
        List<String> messages = result.getMessages();
        for (int i = 0; i < messages.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(escape(messages.get(i))).append('"');
        }
        json.append("]}");
        return json.toString();
    }

    public static String writeError(String message) {
        return "{\"error\":\"" + escape(message) + "\"}";
    }

    private static void append(StringBuilder json, String key, String value) {
        if (json.charAt(json.length() - 1) != '{') {
            json.append(',');
        }
        json.append('"').append(key).append("\":\"").append(escape(value)).append('"');
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}
