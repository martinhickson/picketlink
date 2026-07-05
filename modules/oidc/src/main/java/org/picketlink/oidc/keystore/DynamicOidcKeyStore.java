package org.picketlink.oidc.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.cxf.Bus;
import org.apache.cxf.rs.security.jose.common.JoseConstants;
import org.apache.cxf.rt.security.rs.RSSecurityConstants;
import org.picketlink.oidc.OidcDemoConstants;

/**
 * Mutable OIDC signing keystore. CXF {@code KeyManagementUtils} caches {@link KeyStore}
 * instances per exchange; {@link OidcKeyStoreInstrumentation} routes loads here so admin
 * rotation takes effect without restarting the server.
 */
public final class DynamicOidcKeyStore {

    private static volatile DynamicOidcKeyStore global;

    private final Path keystorePath;
    private final char[] storePassword;
    private final AtomicLong generation = new AtomicLong();
    private volatile KeyStore keyStore;
    private volatile String activeAlias;
    private volatile Bus bus;

    private DynamicOidcKeyStore(Path keystorePath, char[] storePassword, KeyStore keyStore, String activeAlias) {
        this.keystorePath = keystorePath;
        this.storePassword = storePassword.clone();
        this.keyStore = keyStore;
        this.activeAlias = activeAlias;
        this.generation.set(1L);
    }

    public static DynamicOidcKeyStore getGlobal() {
        return global;
    }

    public static void setGlobal(DynamicOidcKeyStore store) {
        global = store;
    }

    public static DynamicOidcKeyStore load(Path keystorePath, String storePassword, String activeAlias)
            throws Exception {
        if (keystorePath == null || !Files.isRegularFile(keystorePath)) {
            throw new IllegalArgumentException("Missing OIDC signing keystore: " + keystorePath);
        }
        KeyStore ks = KeyStore.getInstance(OidcDemoConstants.KEYSTORE_TYPE);
        try (InputStream in = Files.newInputStream(keystorePath)) {
            ks.load(in, storePassword.toCharArray());
        }
        DynamicOidcKeyStore store = new DynamicOidcKeyStore(
                keystorePath.toAbsolutePath().normalize(),
                storePassword.toCharArray(),
                ks,
                activeAlias);
        global = store;
        return store;
    }

    public void bindBus(Bus bus) {
        this.bus = bus;
        applyConfiguration();
    }

    /** CXF resolves JOSE keystore settings from {@link Bus} contextual properties, not only system properties. */
    public void applyConfiguration() {
        System.setProperty(RSSecurityConstants.RSSEC_KEY_STORE_TYPE, OidcDemoConstants.KEYSTORE_TYPE);
        System.setProperty(RSSecurityConstants.RSSEC_KEY_STORE_FILE, keystorePath.toString());
        System.setProperty(RSSecurityConstants.RSSEC_KEY_STORE_PSWD, new String(storePassword));
        System.setProperty(RSSecurityConstants.RSSEC_KEY_STORE_ALIAS, activeAlias);
        System.setProperty(RSSecurityConstants.RSSEC_KEY_PSWD, OidcDemoConstants.KEYSTORE_KEY_PASSWORD);
        if (bus != null) {
            bus.setProperty(RSSecurityConstants.RSSEC_KEY_STORE_TYPE, OidcDemoConstants.KEYSTORE_TYPE);
            bus.setProperty(RSSecurityConstants.RSSEC_KEY_STORE_FILE, keystorePath.toString());
            bus.setProperty(RSSecurityConstants.RSSEC_KEY_STORE_PSWD, new String(storePassword));
            bus.setProperty(RSSecurityConstants.RSSEC_KEY_STORE_ALIAS, activeAlias);
            bus.setProperty(RSSecurityConstants.RSSEC_KEY_PSWD, OidcDemoConstants.KEYSTORE_KEY_PASSWORD);
            bus.setProperty(JoseConstants.RSSEC_SIGNATURE_ALGORITHM, "RS256");
        }
    }

    /** @deprecated use {@link #applyConfiguration()} */
    @Deprecated
    public void applySystemProperties() {
        applyConfiguration();
    }

    public boolean manages(String keystoreFileProperty) {
        return keystoreFileProperty != null
                && keystorePath.toString().equals(keystoreFileProperty);
    }

    public KeyStore currentKeyStore() {
        return keyStore;
    }

    public long generation() {
        return generation.get();
    }

    public String activeAlias() {
        return activeAlias;
    }

    public Path keystorePath() {
        return keystorePath;
    }

    public List<OidcKeyInfo> listKeys() throws Exception {
        List<OidcKeyInfo> keys = new ArrayList<>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!keyStore.isKeyEntry(alias)) {
                continue;
            }
            Certificate cert = keyStore.getCertificate(alias);
            Instant notAfter = null;
            if (cert instanceof X509Certificate x509) {
                notAfter = x509.getNotAfter().toInstant();
            }
            keys.add(new OidcKeyInfo(alias, alias.equals(activeAlias), notAfter));
        }
        keys.sort((a, b) -> Boolean.compare(b.active(), a.active()));
        return Collections.unmodifiableList(keys);
    }

    public OidcKeyRotationResult rotateSigningKey(int validityDays) throws Exception {
        String newAlias = activeAlias + "-" + Instant.now().getEpochSecond();
        runKeytool(
                "-genkeypair",
                "-alias", newAlias,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", Integer.toString(Math.max(validityDays, 1)),
                "-keystore", keystorePath.toString(),
                "-storepass", new String(storePassword),
                "-keypass", OidcDemoConstants.KEYSTORE_KEY_PASSWORD,
                "-dname", "CN=PicketLink OIDC Demo Signing",
                "-ext", "BasicConstraints=ca:true");
        reloadFromDisk(newAlias);
        applyConfiguration();
        generation.incrementAndGet();
        return new OidcKeyRotationResult(newAlias, generation.get(), listKeys());
    }

    private void reloadFromDisk(String newActiveAlias) throws Exception {
        KeyStore reloaded = KeyStore.getInstance(OidcDemoConstants.KEYSTORE_TYPE);
        try (InputStream in = Files.newInputStream(keystorePath)) {
            reloaded.load(in, storePassword);
        }
        this.keyStore = reloaded;
        this.activeAlias = newActiveAlias;
    }

    private static void runKeytool(String... args) throws IOException, InterruptedException {
        Path keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
        List<String> command = new ArrayList<>(args.length + 1);
        command.add(keytool.toString());
        Collections.addAll(command, args);
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();
        String output;
        try (InputStream in = process.getInputStream()) {
            output = new String(in.readAllBytes());
        }
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IOException("keytool failed (" + exit + "): " + output);
        }
    }

    public void persist() throws Exception {
        KeyStore copy = KeyStore.getInstance(keyStore.getType());
        copy.load(null, null);
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                copy.setKeyEntry(alias, keyStore.getKey(alias, storePassword), storePassword,
                        keyStore.getCertificateChain(alias));
            } else {
                copy.setCertificateEntry(alias, keyStore.getCertificate(alias));
            }
        }
        try (OutputStream out = Files.newOutputStream(keystorePath)) {
            copy.store(out, storePassword);
        }
        reloadFromDisk(activeAlias);
        generation.incrementAndGet();
    }
}
