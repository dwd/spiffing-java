package io.cridland.spiffing;

import java.util.*;

import org.w3c.dom.Element;

public final class Tag {
    final Markings markings;
    final List<Category> categories = new ArrayList<>();
    private final TagSet tagSet;
    private final String name;
    private final TagType type;
    private final boolean bitSet;

    Tag(TagSet ts, Element e) {
        tagSet = ts;
        name = Xml.required(e, "name");
        type = TagType.policy(e);
        markings = Markings.parse(e);
        String encoding = type == TagType.informative ? Xml.required(e, "tag7Encoding") : "";
        if (type == TagType.informative && !Set.of("bitSetAttributes", "securityAttributes").contains(encoding))
            throw new SpiffingException("Unknown tag7Encoding");
        bitSet = encoding.equals("bitSetAttributes");
    }

    public TagSet tagSet() {
        return tagSet;
    }

    public String name() {
        return name;
    }

    public TagType type() {
        return type;
    }

    public boolean informativeBitSet() {
        return bitSet;
    }

    public List<Category> categories() {
        return List.copyOf(categories);
    }
}
