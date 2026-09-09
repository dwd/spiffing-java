package io.cridland.spiffing;

import java.io.*;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.*;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

final class Xml {
    static final String DEBUG = "http://surevine.com/xmlns/spiffy";
    static final String NATO = "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0";
    static final String CLEARANCE = "urn:nato:stanag:4774:confidentialityclearance:1:0";

    private static DocumentBuilderFactory factory() throws Exception {
        var f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        return f;
    }

    static Element parse(byte[] data) {
        if (data.length == 0) throw new SpiffingException("No data to parse");
        try {
            var b = factory().newDocumentBuilder();
            b.setErrorHandler(new DefaultHandler() {
                @Override
                public void error(SAXParseException e) throws SAXParseException {
                    throw e;
                }

                @Override
                public void fatalError(SAXParseException e) throws SAXParseException {
                    throw e;
                }
            });
            return b.parse(new ByteArrayInputStream(data)).getDocumentElement();
        } catch (Exception e) {
            throw new SpiffingException("Invalid XML: " + e.getMessage(), e);
        }
    }

    static Document document() {
        try {
            return factory().newDocumentBuilder().newDocument();
        } catch (Exception e) {
            throw new SpiffingException("Cannot create XML document", e);
        }
    }

    static List<Element> children(Element e, String name) {
        return children(e, name, e == null ? null : e.getNamespaceURI());
    }

    static List<Element> children(Element e, String name, String ns) {
        var out = new ArrayList<Element>();
        if (e != null) for (Node n = e.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof Element c && name.equals(c.getLocalName()) && Objects.equals(ns, c.getNamespaceURI()))
                out.add(c);
        return out;
    }

    static Element child(Element e, String name) {
        var list = children(e, name);
        if (list.size() != 1) throw new SpiffingException("Expected one " + name);
        return list.getFirst();
    }

    static Element optional(Element e, String name) {
        var list = children(e, name);
        if (list.size() > 1) throw new SpiffingException("Duplicate " + name);
        return list.isEmpty() ? null : list.getFirst();
    }

    static String required(Element e, String a) {
        if (e == null || !e.hasAttribute(a) || e.getAttribute(a).isEmpty()) throw new SpiffingException("Missing " + a);
        return e.getAttribute(a);
    }

    static String attr(Element e, String a, String fallback) {
        return e.hasAttribute(a) ? e.getAttribute(a) : fallback;
    }

    static Element add(Node parent, String ns, String name, String text) {
        Document d = parent instanceof Document doc ? doc : parent.getOwnerDocument();
        var e = d.createElementNS(ns, name);
        if (text != null) e.setTextContent(text);
        parent.appendChild(e);
        return e;
    }

    static byte[] write(Document d) {
        try {
            var f = TransformerFactory.newInstance();
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            var t = f.newTransformer();
            t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            t.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            var out = new ByteArrayOutputStream();
            t.transform(new DOMSource(d), new StreamResult(out));
            return out.toByteArray();
        } catch (Exception e) {
            throw new SpiffingException("Cannot write XML", e);
        }
    }
}
