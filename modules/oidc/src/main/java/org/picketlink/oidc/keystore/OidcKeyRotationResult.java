package org.picketlink.oidc.keystore;

import java.util.List;

public record OidcKeyRotationResult(String activeAlias, long generation, List<OidcKeyInfo> keys) {
}
