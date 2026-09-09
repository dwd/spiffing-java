package io.cridland.spiffing;

import org.w3c.dom.Element;

/**
 * Classification defined by one policy. Hierarchy controls clearance display order.
 */
public final class Classification {
    final Element source;
    final Markings markings;
    private final Lacv lacv;
    private final String name;
    private final long hierarchy;

    Classification(Element e) {
        source = e;
        lacv = Lacv.parse(Xml.required(e, "lacv"));
        name = Xml.required(e, "name");
        hierarchy = Long.parseLong(Xml.required(e, "hierarchy"));
        markings = Markings.parse(e);
    }

    public Lacv lacv() {
        return lacv;
    }

    public String name() {
        return name;
    }

    public long hierarchy() {
        return hierarchy;
    }

    public boolean obsolete() {
        return Boolean.parseBoolean(source.getAttribute("obsolete"));
    }

    public String color() {
        return source.getAttribute("color");
    }
}
