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
package org.picketlink.identity.federation.web.config;

import org.picketlink.common.constants.JBossSAMLURIConstants;

/**
 * <p>
 * An instance of {@link SAMLConfigurationProvider} that can be used to generate the SP configuration for the HTTP-POST
 * binding
 * using SAML2 Metadata.
 * </p>
 * <p>
 * This provider uses the following in sequence whichever is available:
 * <ol>
 * <li>a sp-metadata.xml file available in its immediate class path.</li>
 * <li></li>
 * </ol>
 * </p>
 *
 * @author Anil Saldhana
 * @since Feb 15, 2012
 */
public class SPPostMetadataConfigurationProvider extends AbstractSPMetadataConfigurationProvider {

    @Override
    protected String getBindingURI() {
        return JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
    }
}