package org.picketlink.test.config.federation;

import org.junit.Assert;
import org.junit.Test;
import org.picketlink.config.federation.MetadataPublishingType;
import org.picketlink.config.federation.SPType;
import org.picketlink.config.federation.parsers.SAMLConfigParser;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class MetadataPublishingConfigTestCase {

    @Test
    public void defaultsWhenMetadataPublishingElementAbsent() {
        MetadataPublishingType publishing = new MetadataPublishingType();
        Assert.assertTrue(publishing.isXmlEnabled());
        Assert.assertFalse(publishing.isAdminJsonEnabled());
        Assert.assertTrue(publishing.isAdminJsonRequireAuth());
    }

    @Test
    public void parsesMetadataPublishingAttributes() throws Exception {
        String xml = "<PicketLinkSP xmlns=\"urn:picketlink:identity-federation:config:2.1\">"
                + "<MetadataPublishing XmlEnabled=\"false\" AdminJsonEnabled=\"true\" AdminJsonRequireAuth=\"false\"/>"
                + "</PicketLinkSP>";
        SPType sp = (SPType) new SAMLConfigParser().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        MetadataPublishingType publishing = sp.getMetadataPublishing();
        Assert.assertNotNull(publishing);
        Assert.assertFalse(publishing.isXmlEnabled());
        Assert.assertTrue(publishing.isAdminJsonEnabled());
        Assert.assertFalse(publishing.isAdminJsonRequireAuth());
    }

    @Test
    public void cryptoPolicyDefaultsFalseOnProvider() throws Exception {
        String xml = "<PicketLinkSP xmlns=\"urn:picketlink:identity-federation:config:2.1\"/>";
        SPType sp = (SPType) new SAMLConfigParser().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Assert.assertFalse(sp.isAcceptLegacyAlgorithms());
        Assert.assertFalse(sp.isEnableLegacySigning());
    }

    @Test
    public void parsesProviderCryptoPolicyAttributes() throws Exception {
        String xml = "<PicketLinkSP xmlns=\"urn:picketlink:identity-federation:config:2.1\""
                + " AcceptLegacyAlgorithms=\"true\" EnableLegacySigning=\"true\"/>";
        SPType sp = (SPType) new SAMLConfigParser().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Assert.assertTrue(sp.isAcceptLegacyAlgorithms());
        Assert.assertTrue(sp.isEnableLegacySigning());
    }
}
