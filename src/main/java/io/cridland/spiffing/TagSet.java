package io.cridland.spiffing;

import java.util.*;

import org.w3c.dom.Element;

public final class TagSet {
    final Spif policy;
    final List<Tag> tags = new ArrayList<>();
    private final String id, name;

    TagSet(Spif policy, Element e) {
        this.policy = policy;
        id = Xml.required(e, "id");
        name = Xml.required(e, "name");
    }

    public String id() {
        return id;
    }

    public String name() {
        return name;
    }

    public List<Tag> tags() {
        return List.copyOf(tags);
    }

    public List<Category> categories(TagType type) {
        return tags.stream().filter(t -> t.type() == type).flatMap(t -> t.categories.stream()).toList();
    }

    public Category categoryLookup(TagType type, long lacv) {
        return categoryLookup(type, new Lacv(lacv));
    }

    public Category categoryLookup(TagType type, Lacv lacv) {
        return categories(type).stream().filter(c -> c.lacv().equals(lacv)).findFirst().orElseThrow(() -> new SpiffingException("Unknown category: " + id + "/" + type + "/" + lacv));
    }

    public Category categoryLookup(TagType type, String name) {
        var matches = tags.stream().filter(t -> t.type().normalized() == type.normalized()).flatMap(t -> t.categories.stream()).filter(c -> c.name().equals(name)).toList();
        if (matches.size() != 1) throw new SpiffingException("Unknown or ambiguous category name: " + name);
        return matches.getFirst();
    }
}
