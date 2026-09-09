package io.cridland.spiffing;

import org.w3c.dom.Element;

/**
 * Policy-owned category. Identity is scoped to the policy instance.
 */
public final class Category {
    final Element source;
    final Markings markings;
    final int ordinal;
    private final Tag tag;
    private final Lacv lacv;
    private final String name;

    Category(Tag tag, Element e, int ordinal) {
        this.tag = tag;
        source = e;
        this.ordinal = ordinal;
        lacv = Lacv.parse(Xml.required(e, "lacv"));
        name = Xml.required(e, "name");
        markings = Markings.parse(e);
    }

    public Tag tag() {
        return tag;
    }

    public Lacv lacv() {
        return lacv;
    }

    public String name() {
        return name;
    }
}
