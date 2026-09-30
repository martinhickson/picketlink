/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2026 PicketLink contributors.
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
package org.picketlink.identity.federation.web.filters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.test.identity.federation.web.mock.MockHttpSession;

public class IDPFilterRoleSessionTestCase {

    @Test
    public void emptyGenerationDoesNotReplaceExistingRoles() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(GeneralConstants.ROLES_ID, Arrays.asList("sonata-web"));

        new IDPFilter().rememberGeneratedRoles(session, Collections.<String>emptyList());

        assertEquals(Arrays.asList("sonata-web"), session.getAttribute(GeneralConstants.ROLES_ID));
    }

    @Test
    public void emptyGenerationDoesNotStampTheSession() {
        MockHttpSession session = new MockHttpSession();

        new IDPFilter().rememberGeneratedRoles(session, null);

        assertNull(session.getAttribute(GeneralConstants.ROLES_ID));
    }

    @Test
    public void nonEmptyGenerationIsStored() {
        MockHttpSession session = new MockHttpSession();
        List<String> roles = Arrays.asList("sonata-staff", "sonata-agent");

        new IDPFilter().rememberGeneratedRoles(session, roles);

        assertEquals(roles, session.getAttribute(GeneralConstants.ROLES_ID));
    }
}
