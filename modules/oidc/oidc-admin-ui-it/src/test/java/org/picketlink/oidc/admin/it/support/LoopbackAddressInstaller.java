package org.picketlink.oidc.admin.it.support;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

/**
 * Ensures the dedicated loopback IP exists on {@code lo} before WildFly starts.
 */
public final class LoopbackAddressInstaller {

    private static final List<String> REQUIRED_ADDRESSES = Collections.singletonList("127.0.0.113");

    private LoopbackAddressInstaller() {
    }

    public static void main(String[] args) throws Exception {
        for (String address : REQUIRED_ADDRESSES) {
            ensureAddress(address);
        }
    }

    private static void ensureAddress(String address) throws Exception {
        if (isPresent(address)) {
            return;
        }
        ProcessBuilder add = new ProcessBuilder("ip", "addr", "add", address + "/8", "dev", "lo");
        add.redirectErrorStream(true);
        Process process = add.start();
        drain(process);
        int exitCode = process.waitFor();
        if (exitCode != 0 && !isPresent(address)) {
            throw new IllegalStateException(
                    "Loopback IP " + address + " is required on lo. Run: sudo ip addr add "
                            + address + "/8 dev lo");
        }
    }

    private static boolean isPresent(String address) throws Exception {
        ProcessBuilder show = new ProcessBuilder("ip", "addr", "show", "dev", "lo");
        show.redirectErrorStream(true);
        Process process = show.start();
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append('\n');
        }
        process.waitFor();
        return output.toString().contains(" inet " + address + "/");
    }

    private static void drain(Process process) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        while (reader.readLine() != null) {
            // discard
        }
        process.waitFor();
    }
}
