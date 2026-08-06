/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.identity.federation.core.saml.md.providers;

import org.picketlink.config.federation.PicketLinkType;
import org.picketlink.config.federation.ProviderType;
import org.picketlink.common.util.StringUtil;
import org.picketlink.identity.federation.core.interfaces.IMetadataProvider;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IDPSSODescriptorType;

import java.io.InputStream;
import java.net.URI;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Map;

/**
 * Metadata provider that generates IDP metadata from {@code picketlink.xml} configuration.
 * <p>
 * When {@code EntityId} is omitted, it defaults to {@code IdentityURL}. PicketLink IdP runtime
 * assertions use {@code IdentityURL} as Issuer, so published metadata must match unless an
 * explicit {@code EntityId} override is supplied.
 */
public class IDPMetadataProvider extends AbstractMetadataProvider implements IMetadataProvider<EntityDescriptorType> {

    private static final String ENTITY_ID_KEY = "EntityId";
    private static final String BINDING_TYPE_KEY = "BindingType";
    private static final String WANT_AUTHN_REQUESTS_SIGNED_KEY = "WantAuthnRequestsSigned";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

    private String entityId;
    private String identityUrl;
    private String bindingUri;
    private String sloResponseLocation;
    private boolean wantAuthnRequestsSigned;
    private PicketLinkType picketLinkType;

    @Override
    public void init(Map<String, String> options) {
        super.init(options);

        ProviderType providerType = MetadataProviderUtils.getProviderType(picketLinkType);
        if (providerType == null) {
            throw new RuntimeException("IDP configuration missing");
        }

        identityUrl = MetadataProviderUtils.getIdentityURL(providerType);
        if (identityUrl == null) {
            throw new RuntimeException("IdentityURL cannot be null");
        }

        entityId = options.get(ENTITY_ID_KEY);
        if (StringUtil.isNullOrEmpty(entityId)) {
            // PicketLink IdP Issuer is IdentityURL; keep published entityID aligned by default.
            entityId = identityUrl;
        }

        String bindingType = options.get(BINDING_TYPE_KEY);
        if (bindingType != null) {
            bindingUri = MetadataProviderUtils.bindingUriFromType(bindingType);
        } else {
            bindingUri = MetadataProviderUtils.getBindingURI(providerType);
        }
        if (bindingUri == null) {
            throw new RuntimeException("bindingURI cannot be null");
        }

        sloResponseLocation = MetadataProviderUtils.getSingleLogoutServiceResponseLocation(providerType);

        String wantSigned = options.get(WANT_AUTHN_REQUESTS_SIGNED_KEY);
        if (wantSigned != null) {
            wantAuthnRequestsSigned = Boolean.parseBoolean(wantSigned);
        }
    }

    @Override
    public EntityDescriptorType getMetaData() {
        ArrayList<String> protocols = new ArrayList<String>();
        protocols.add(PROTOCOL);
        IDPSSODescriptorType idpSSO = new IDPSSODescriptorType(protocols);
        idpSSO.setWantAuthnRequestsSigned(wantAuthnRequestsSigned);

        idpSSO.addSingleSignOnService(new EndpointType(URI.create(bindingUri), URI.create(identityUrl)));

        EndpointType sloEndpoint = new EndpointType(URI.create(bindingUri), URI.create(identityUrl));
        if (sloResponseLocation != null) {
            sloEndpoint.setResponseLocation(URI.create(sloResponseLocation));
        }
        idpSSO.addSingleLogoutService(sloEndpoint);

        EntityDescriptorType.EDTDescriptorChoiceType edtDescChoice =
                new EntityDescriptorType.EDTDescriptorChoiceType(idpSSO);
        EntityDescriptorType.EDTChoiceType edtChoice = EntityDescriptorType.EDTChoiceType.oneValue(edtDescChoice);

        EntityDescriptorType entityDescriptor = new EntityDescriptorType(entityId);
        entityDescriptor.addChoiceType(edtChoice);
        return entityDescriptor;
    }

    public void setPicketLinkConf(PicketLinkType picketLinkType) {
        this.picketLinkType = picketLinkType;
    }

    @Override
    public void injectFileStream(InputStream fileStream) {
    }

    @Override
    public boolean isMultiple() {
        return false;
    }

    @Override
    public String requireFileInjection() {
        return null;
    }

    @Override
    public void injectSigningKey(PublicKey publicKey) {
    }

    @Override
    public void injectEncryptionKey(PublicKey publicKey) {
    }
}
