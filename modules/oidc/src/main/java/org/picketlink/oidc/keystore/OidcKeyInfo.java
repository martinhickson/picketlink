package org.picketlink.oidc.keystore;

import java.time.Instant;

public record OidcKeyInfo(String alias, boolean active, Instant notAfter) {
}
