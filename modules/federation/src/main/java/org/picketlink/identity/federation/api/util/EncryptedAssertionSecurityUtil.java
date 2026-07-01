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
package org.picketlink.identity.federation.api.util;

/**
 * Security controls for SAML encrypted assertion handling.
 */
public final class EncryptedAssertionSecurityUtil {

    /**
     * When {@code true}, encrypted assertions in POST binding responses whose root
     * {@code Response} is not signed must carry a valid signature after decryption
     * (mitigates encrypted assertion injection when only a sibling assertion is signed).
     */
    public static final boolean ENCRYPTED_ASSERTION_SECURITY_CHECK_ENABLED = true;

    private EncryptedAssertionSecurityUtil() {
    }
}
