package org.picketlink.idm.admin.standalone;

import java.util.Objects;

/**
 * Describes XML to insert immediately before the closing tag of a parent element inside
 * {@code standalone.xml}. Insertions are skipped when {@link #idempotencyMarker} is already present.
 */
public final class XmlInsertion {

    private final XmlLocation location;
    private final String idempotencyElement;
    private final String idempotencyName;
    private final String fragmentXml;

    public XmlInsertion(XmlLocation location, String idempotencyElement, String idempotencyName,
            String fragmentXml) {
        this.location = Objects.requireNonNull(location, "location");
        this.idempotencyElement = Objects.requireNonNull(idempotencyElement, "idempotencyElement");
        this.idempotencyName = Objects.requireNonNull(idempotencyName, "idempotencyName");
        this.fragmentXml = Objects.requireNonNull(fragmentXml, "fragmentXml");
    }

    public XmlLocation getLocation() {
        return location;
    }

    public String getIdempotencyElement() {
        return idempotencyElement;
    }

    public String getIdempotencyName() {
        return idempotencyName;
    }

    public String getFragmentXml() {
        return fragmentXml;
    }

    public enum SubsystemKind {
        ELYTRON,
        UNDERTOW
    }

    public enum XmlLocation {
        ELYTRON_SECURITY_DOMAINS(SubsystemKind.ELYTRON, "security-domains"),
        ELYTRON_SECURITY_REALMS(SubsystemKind.ELYTRON, "security-realms"),
        ELYTRON_MAPPERS(SubsystemKind.ELYTRON, "mappers"),
        ELYTRON_HTTP(SubsystemKind.ELYTRON, "http"),
        UNDERTOW_APPLICATION_SECURITY_DOMAINS(SubsystemKind.UNDERTOW, "application-security-domains");

        private final SubsystemKind subsystem;
        private final String parentLocalName;

        XmlLocation(SubsystemKind subsystem, String parentLocalName) {
            this.subsystem = subsystem;
            this.parentLocalName = parentLocalName;
        }

        public SubsystemKind getSubsystem() {
            return subsystem;
        }

        public String getParentLocalName() {
            return parentLocalName;
        }
    }
}
