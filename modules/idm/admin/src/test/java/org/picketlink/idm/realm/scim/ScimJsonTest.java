package org.picketlink.idm.realm.scim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ScimJsonTest {

    @Test
    void parsesListResponseResources() {
        String json = """
                {
                  "totalResults": 2,
                  "Resources": [
                    {
                      "id": "u1",
                      "userName": "alice",
                      "active": true,
                      "groups": [{"value": "role1"}]
                    },
                    {
                      "id": "u2",
                      "displayName": "bob",
                      "active": false
                    }
                  ]
                }
                """;
        var users = ScimJson.parseListResponse(json);
        assertEquals(2, users.size());
        assertEquals("alice", users.get(0).loginName());
        assertEquals("role1", users.get(0).getGroups().get(0));
        assertEquals("bob", users.get(1).loginName());
    }

    @Test
    void parsesRolesExtensionResources() {
        String json = """
                {
                  "Resources": [
                    {"id": "r1", "displayName": "administrator"},
                    {"id": "r2", "displayName": "operator"}
                  ]
                }
                """;
        var roles = ScimJson.parseListResponse(json);
        assertEquals(2, roles.size());
        assertEquals("administrator", roles.get(0).getDisplayName());
    }

    @Test
    void parsesSingleResourceResponse() {
        ScimRealmClient.ScimResource user = ScimJson.parseResource("""
                {"id":"u1","userName":"alice","active":true}
                """);
        assertEquals("u1", user.getId());
        assertTrue(user.isActive());
    }
}
