package org.picketlink.auth.oauth.jwt;

import java.util.ArrayList;
import java.util.List;

/**
 * RS256 signer whose active key can change. Verification and JWKS keep every key that was
 * published, so tokens signed before a rotation still verify.
 */
public final class RotatingRsaJwtSigner implements JwtSigner {

    private volatile List<RsaJwtSigner> keys = List.of();
    private volatile RsaJwtSigner active;

    public void replace(List<RsaJwtSigner> keys, String activeKeyId) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("at least one RSA signing key is required");
        }
        RsaJwtSigner next = null;
        for (RsaJwtSigner key : keys) {
            if (key.keyId().equals(activeKeyId)) {
                next = key;
            }
        }
        if (next == null) {
            throw new IllegalArgumentException("Active signing key is not an RSA key: " + activeKeyId);
        }
        this.keys = List.copyOf(keys);
        this.active = next;
    }

    @Override
    public String algorithm() {
        return "RS256";
    }

    @Override
    public String keyId() {
        RsaJwtSigner current = active;
        if (current == null) {
            throw new IllegalStateException("No signing key");
        }
        return current.keyId();
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        RsaJwtSigner current = active;
        if (current == null) {
            throw new IllegalStateException("No signing key");
        }
        return current.sign(signingInput);
    }

    @Override
    public boolean verify(byte[] signingInput, byte[] signature) {
        for (RsaJwtSigner key : keys) {
            if (key.verify(signingInput, signature)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String jwks() {
        RsaJwtSigner current = active;
        if (current == null) {
            return "{\"keys\":[]}";
        }
        StringBuilder json = new StringBuilder("{\"keys\":[");
        json.append(current.jwk());
        for (RsaJwtSigner key : keys) {
            if (!key.keyId().equals(current.keyId())) {
                json.append(',').append(key.jwk());
            }
        }
        json.append("]}");
        return json.toString();
    }

    public List<String> keyIds() {
        List<String> ids = new ArrayList<>();
        for (RsaJwtSigner key : keys) {
            ids.add(key.keyId());
        }
        return ids;
    }
}
