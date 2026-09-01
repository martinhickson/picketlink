package org.picketlink.auth.oauth.store;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Minimal self-signed certificate so keystore key entries have a certificate chain. */
final class SelfSignedCertificate {

    private SelfSignedCertificate() {
    }

    static X509Certificate create(KeyPair keyPair, String subjectDn, int validityDays)
            throws Exception {
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new org.bouncycastle.asn1.x500.X500Name(subjectDn),
                BigInteger.valueOf(new SecureRandom().nextLong()),
                Date.from(now),
                Date.from(now.plusSeconds(validityDays * 24L * 3600L)),
                new org.bouncycastle.asn1.x500.X500Name(subjectDn),
                keyPair.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate())));
    }
}
