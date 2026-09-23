package org.picketlink.auth.oauth.jwt;

public interface JwtSigner {

    String algorithm();

    String keyId();

    byte[] sign(byte[] signingInput);

    boolean verify(byte[] signingInput, byte[] signature);

    String jwks();
}
