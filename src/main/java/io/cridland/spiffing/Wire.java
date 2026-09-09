package io.cridland.spiffing;

import java.util.*;

import org.w3c.dom.Element;

/**
 * Shared XML and format dispatch for labels and clearances.
 */
final class Wire {
    record Value(Spif policy, List<Lacv> classes, List<Category> categories) {
    }

    static Label parseLabel(byte[] data, Format format, Site site) {
        Value v = parse(data, format, site, false);
        if (v.classes.size() != 1) throw new SpiffingException("Label requires one classification");
        var label = new Label(v.policy, v.classes.get(0));
        v.categories.forEach(label::addCategory);
        return label;
    }

    static Clearance parseClearance(byte[] data, Format format, Site site) {
        Value v = parse(data, format, site, true);
        var c = new Clearance(v.policy);
        v.classes.forEach(c::addClassification);
        v.categories.forEach(c::addCategory);
        return c;
    }

    private static Value parse(byte[] data, Format format, Site site, boolean clearance) {
        Objects.requireNonNull(data);
        Objects.requireNonNull(format);
        Objects.requireNonNull(site);
        if (data.length == 0) throw new SpiffingException("No data to parse");
        if (format == Format.ANY) {
            // ASN.1 roots are SET (label) and SEQUENCE (clearance); XML may use a BOM or UTF-16.
            format = (data[0] == 0x30 || data[0] == 0x31) ? Format.BER : Format.XML;
        }
        if (format == Format.BER || format == Format.DER) return AsnCodec.read(data, site, clearance);
        var root = Xml.parse(data);
        var ns = root.getNamespaceURI();
        if (Xml.DEBUG.equals(ns) && format != Format.NATO) return debug(root, site, clearance);
        if ((clearance ? Xml.CLEARANCE : Xml.NATO).equals(ns)) return nato(root, site, clearance);
        throw new SpiffingException("Unknown XML namespace: " + ns);
    }

    private static Value debug(Element root, Site site, boolean clearance) {
        if (!root.getLocalName().equals(clearance ? "clearance" : "label"))
            throw new SpiffingException("Incorrect XML root");
        var policy = site.spif(Xml.required(Xml.child(root, "policy"), "id"));
        var classes = new ArrayList<Lacv>();
        var cats = new ArrayList<Category>();
        for (var e : Xml.children(root, "classification")) classes.add(Lacv.parse(Xml.required(e, "lacv")));
        for (var e : Xml.children(root, "tag"))
            cats.add(policy.tagSetLookup(Xml.required(e, "id"))
                    .categoryLookup(TagType.parse(Xml.required(e, "type")), Lacv.parse(Xml.required(e, "lacv"))));
        return new Value(policy, classes, cats);
    }

    private static Element one(Element e, String name, String ns) {
        var matches = Xml.children(e, name, ns);
        if (matches.size() != 1) throw new SpiffingException("Expected one " + name);
        return matches.get(0);
    }

    private static Value nato(Element root, Site site, boolean clearance) {
        if (!root.getLocalName().equals(clearance ? "ConfidentialityClearance" : "originatorConfidentialityLabel"))
            throw new SpiffingException("Incorrect NATO XML root");
        var info = clearance ? root : Xml.child(root, "ConfidentialityInformation");
        var ident = one(info, "PolicyIdentifier", Xml.NATO);
        var policy = site.spifByName(ident.getTextContent());
        String uri = Xml.attr(ident, "URI", ident.getAttribute("URL"));
        if (uri.startsWith("urn:oid:") && !policy.policyId().equals(uri.substring(8)))
            throw new SpiffingException("Policy mismatch: " + uri);
        var classes = new ArrayList<Lacv>();
        var cats = new ArrayList<Category>();
        var holder = clearance ? Xml.child(root, "ClassificationList") : info;
        for (var e : Xml.children(holder, "Classification", Xml.NATO))
            classes.add(policy.classificationLookup(e.getTextContent()).lacv());
        for (var e : Xml.children(info, "Category", Xml.NATO)) {
            var type = switch (Xml.required(e, "Type")) {
                case "RESTRICTIVE" -> TagType.restrictive;
                case "PERMISSIVE" -> TagType.permissive;
                case "INFORMATIVE" -> TagType.informative;
                default -> throw new SpiffingException("Unknown NATO category type");
            };
            var ts = policy.tagSetLookupByName(Xml.required(e, "TagName"));
            for (var v : Xml.children(e, "GenericValue")) cats.add(ts.categoryLookup(type, v.getTextContent()));
        }
        return new Value(policy, classes, cats);
    }

    static byte[] write(Spif policy, Collection<Lacv> classes, Set<Category> categories, boolean clearance, Format format) {
        Objects.requireNonNull(format);
        if (format == Format.ANY) throw new SpiffingException("ANY is an input format only");
        if (format == Format.BER || format == Format.DER) return AsnCodec.write(policy, classes, categories, clearance);
        var doc = Xml.document();
        if (format == Format.XML) {
            var root = Xml.add(doc, Xml.DEBUG, clearance ? "clearance" : "label", null);
            Xml.add(root, Xml.DEBUG, "policy", null).setAttribute("id", policy.policyId());
            for (var c : classes) Xml.add(root, Xml.DEBUG, "classification", null).setAttribute("lacv", c.toString());
            for (var c : categories) {
                var tag = Xml.add(root, Xml.DEBUG, "tag", null);
                tag.setAttribute("type", c.tag().type().name());
                tag.setAttribute("id", c.tag().tagSet().id());
                tag.setAttribute("lacv", c.lacv().toString());
            }
        } else {
            var root = Xml.add(doc, clearance ? Xml.CLEARANCE : Xml.NATO, clearance ? "ConfidentialityClearance" : "originatorConfidentialityLabel", null);
            var info = clearance ? root : Xml.add(root, Xml.NATO, "ConfidentialityInformation", null);
            Xml.add(info, Xml.NATO, "PolicyIdentifier", policy.name()).setAttribute("URI", "urn:oid:" + policy.policyId());
            var holder = clearance ? Xml.add(root, Xml.CLEARANCE, "ClassificationList", null) : info;
            for (var c : classes) Xml.add(holder, Xml.NATO, "Classification", policy.classificationLookup(c).name());
            record Group(TagSet tagSet, TagType type) {
            }
            Map<Group, List<Category>> groups = new LinkedHashMap<>();
            for (var c : categories)
                groups.computeIfAbsent(new Group(c.tag().tagSet(), c.tag().type().normalized()), k -> new ArrayList<>()).add(c);
            for (var entry : groups.entrySet()) {
                var e = Xml.add(info, Xml.NATO, "Category", null);
                e.setAttribute("TagName", entry.getKey().tagSet.name());
                e.setAttribute("Type", entry.getKey().type.name().toUpperCase(Locale.ROOT));
                for (var c : entry.getValue()) Xml.add(e, Xml.NATO, "GenericValue", c.name());
            }
        }
        return Xml.write(doc);
    }
}
