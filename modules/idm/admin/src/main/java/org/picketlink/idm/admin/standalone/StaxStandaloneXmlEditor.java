package org.picketlink.idm.admin.standalone;

import com.ctc.wstx.api.WstxInputProperties;
import com.ctc.wstx.api.WstxOutputProperties;
import com.ctc.wstx.stax.WstxInputFactory;
import com.ctc.wstx.stax.WstxOutputFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * Applies surgical edits to {@code standalone.xml} by copying StAX events verbatim and inserting
 * new fragments only at explicit closing tags. Uses Woodstox (Apache 2.0) so whitespace and
 * formatting outside edited regions are preserved for readable diffs.
 */
public final class StaxStandaloneXmlEditor {

    public void apply(Path standaloneXml, List<XmlInsertion> insertions) throws IOException {
        if (insertions.isEmpty()) {
            return;
        }
        List<XMLEvent> events = readEvents(standaloneXml);
        List<XmlInsertion> pending = new ArrayList<XmlInsertion>();
        for (XmlInsertion insertion : insertions) {
            if (!containsNamedElement(events, insertion.getIdempotencyElement(), insertion.getIdempotencyName())) {
                pending.add(insertion);
            }
        }
        if (pending.isEmpty()) {
            return;
        }
        for (XmlInsertion insertion : pending) {
            int index = findClosingTagIndex(events, insertion.getLocation());
            if (index < 0) {
                throw new IOException("Could not locate </" + insertion.getLocation().getParentLocalName()
                        + "> in " + insertion.getLocation().getSubsystem() + " subsystem of "
                        + standaloneXml);
            }
            events.addAll(index, parseFragmentEvents(insertion.getFragmentXml()));
        }
        writeEvents(standaloneXml, events);
    }

    public int removeHttpsListeners(Path standaloneXml) throws IOException {
        List<XMLEvent> events = readEvents(standaloneXml);
        List<XMLEvent> filtered = new ArrayList<XMLEvent>(events.size());
        int removed = 0;
        for (int i = 0; i < events.size(); i++) {
            XMLEvent event = events.get(i);
            if (event.isStartElement()) {
                StartElement start = event.asStartElement();
                if ("https-listener".equals(start.getName().getLocalPart())) {
                    removed++;
                    continue;
                }
            }
            if (event.isEndElement()) {
                EndElement end = event.asEndElement();
                if ("https-listener".equals(end.getName().getLocalPart())) {
                    continue;
                }
            }
            filtered.add(event);
        }
        if (removed > 0) {
            writeEvents(standaloneXml, filtered);
        }
        return removed;
    }

    private List<XMLEvent> readEvents(Path file) throws IOException {
        WstxInputFactory inputFactory = new WstxInputFactory();
        inputFactory.setProperty(WstxInputProperties.P_RETURN_NULL_FOR_DEFAULT_NAMESPACE, true);
        inputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
        List<XMLEvent> events = new ArrayList<XMLEvent>();
        try (InputStream input = Files.newInputStream(file)) {
            XMLEventReader reader = inputFactory.createXMLEventReader(input);
            while (reader.hasNext()) {
                events.add(reader.nextEvent());
            }
            reader.close();
        } catch (XMLStreamException ex) {
            throw new IOException("Failed to read " + file, ex);
        }
        return events;
    }

    private void writeEvents(Path file, List<XMLEvent> events) throws IOException {
        WstxOutputFactory outputFactory = new WstxOutputFactory();
        outputFactory.setProperty(WstxOutputProperties.P_USE_DOUBLE_QUOTES_IN_XML_DECL, true);
        try (OutputStream output = Files.newOutputStream(file)) {
            XMLEventWriter writer = outputFactory.createXMLEventWriter(output, "UTF-8");
            for (XMLEvent event : events) {
                writer.add(event);
            }
            writer.flush();
            writer.close();
        } catch (XMLStreamException ex) {
            throw new IOException("Failed to write " + file, ex);
        }
    }

    private List<XMLEvent> parseFragmentEvents(String fragmentXml) throws IOException {
        String wrapped = "<fragments xmlns=\"urn:picketlink:idm:fragments\">" + fragmentXml + "</fragments>";
        WstxInputFactory inputFactory = new WstxInputFactory();
        List<XMLEvent> fragmentEvents = new ArrayList<XMLEvent>();
        try {
            XMLEventReader reader = inputFactory.createXMLEventReader(new StringReader(wrapped));
            int depth = 0;
            while (reader.hasNext()) {
                XMLEvent event = reader.nextEvent();
                if (event.isStartDocument() || event.isEndDocument()) {
                    continue;
                }
                if (event.isStartElement()) {
                    StartElement start = event.asStartElement();
                    if ("fragments".equals(start.getName().getLocalPart())) {
                        depth++;
                        continue;
                    }
                    depth++;
                } else if (event.isEndElement()) {
                    EndElement end = event.asEndElement();
                    if ("fragments".equals(end.getName().getLocalPart())) {
                        break;
                    }
                    depth--;
                }
                if (depth >= 1) {
                    fragmentEvents.add(event);
                }
            }
            reader.close();
        } catch (XMLStreamException ex) {
            throw new IOException("Failed to parse XML fragment", ex);
        }
        return fragmentEvents;
    }

    private static boolean containsNamedElement(List<XMLEvent> events, String localName, String nameValue) {
        for (XMLEvent event : events) {
            if (!event.isStartElement()) {
                continue;
            }
            StartElement start = event.asStartElement();
            if (!localName.equals(start.getName().getLocalPart())) {
                continue;
            }
            Attribute name = start.getAttributeByName(new QName("name"));
            if (name != null && nameValue.equals(name.getValue())) {
                return true;
            }
        }
        return false;
    }

    private static int findClosingTagIndex(List<XMLEvent> events, XmlInsertion.XmlLocation location) {
        boolean inSubsystem = false;
        for (int i = 0; i < events.size(); i++) {
            XMLEvent event = events.get(i);
            if (event.isStartElement()) {
                StartElement start = event.asStartElement();
                if ("subsystem".equals(start.getName().getLocalPart())) {
                    String namespace = start.getName().getNamespaceURI();
                    if (namespace != null && !namespace.isEmpty()
                            && matchesSubsystem(namespace, location.getSubsystem())) {
                        inSubsystem = true;
                    }
                }
            } else if (event.isEndElement()) {
                EndElement end = event.asEndElement();
                if (inSubsystem && location.getParentLocalName().equals(end.getName().getLocalPart())) {
                    return i;
                }
                if ("subsystem".equals(end.getName().getLocalPart()) && inSubsystem) {
                    inSubsystem = false;
                }
            }
        }
        return -1;
    }

    private static boolean matchesSubsystem(String xmlns, XmlInsertion.SubsystemKind kind) {
        if (kind == XmlInsertion.SubsystemKind.ELYTRON) {
            return xmlns.contains("elytron");
        }
        return xmlns.contains("undertow");
    }
}
