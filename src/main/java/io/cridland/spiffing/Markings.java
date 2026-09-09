package io.cridland.spiffing;

import java.util.*;

import org.w3c.dom.Element;

final class Markings {
    record Phrase(int mask, String text) {
    }

    static final class Marking {
        String prefix = "", suffix = "", separator = "";
        final List<Phrase> phrases = new ArrayList<>();

        String phrase(MarkingCode loc, String fallback) {
            for (var p : phrases)
                if ((p.mask & loc.mask) != 0) {
                    if ((p.mask & 8) != 0) return "";
                    return (p.mask & 128) != 0 || p.text == null ? fallback : p.text;
                }
            return fallback;
        }

        boolean flag(MarkingCode loc, MarkingCode flag) {
            for (var p : phrases) if ((p.mask & loc.mask) != 0) return (p.mask & flag.mask) != 0;
            return false;
        }

        String policyPhrase(MarkingCode loc, String fallback) {
            for (var p : phrases) if ((p.mask & (loc.mask | 128)) != 0) return p.text == null ? fallback : p.text;
            return fallback;
        }
    }

    final Map<String, Marking> values = new LinkedHashMap<>();

    Marking get(String language) {
        var m = values.get(language);
        if (m == null) {
            int i = language.indexOf('-');
            if (i < 0) i = language.indexOf('_');
            if (i >= 0) m = values.get(language.substring(0, i));
        }
        return m == null ? values.get("") : m;
    }

    static Markings parse(Element e) {
        var result = new Markings();
        var qualifiers = new ArrayList<Element>();
        for (var q : Xml.children(e, "markingQualifier")) qualifiers.addAll(Xml.children(q, "qualifier"));
        for (var q : qualifiers) {
            var m = result.values.computeIfAbsent(q.getAttribute("xml:lang"), k -> new Marking());
            set(m, q, false);
        }
        for (var data : Xml.children(e, "markingData")) {
            var m = result.values.computeIfAbsent(data.getAttribute("xml:lang"), k -> new Marking());
            int mask = 0;
            boolean location = false;
            for (var code : Xml.children(data, "code")) {
                String c = code.getTextContent();
                if (c.equals("pageTopBottom")) {
                    mask |= 3;
                    location = true;
                } else {
                    MarkingCode mc;
                    try {
                        mc = MarkingCode.valueOf(c);
                    } catch (Exception ex) {
                        throw new SpiffingException("Unknown marking code: " + c);
                    }
                    mask |= mc.mask;
                    if (mc == MarkingCode.pageTop || mc == MarkingCode.pageBottom || mc == MarkingCode.documentStart || mc == MarkingCode.documentEnd || mc == MarkingCode.noMarkingDisplay)
                        location = true;
                }
            }
            if (!location) mask |= 2;
            m.phrases.add(new Phrase(mask, data.hasAttribute("phrase") ? data.getAttribute("phrase") : null));
        }
        for (var entry : result.values.entrySet())
            if (!entry.getKey().isEmpty())
                for (var q : qualifiers) if (q.getAttribute("xml:lang").isEmpty()) set(entry.getValue(), q, true);
        return result;
    }

    static void set(Marking m, Element q, boolean defaults) {
        String text = q.getAttribute("markingQualifier");
        switch (q.getAttribute("qualifierCode")) {
            case "prefix" -> {
                if (!defaults || m.prefix.isEmpty()) m.prefix = text;
            }
            case "suffix" -> {
                if (!defaults || m.suffix.isEmpty()) m.suffix = text;
            }
            case "separator" -> {
                if (!defaults || m.separator.isEmpty()) m.separator = text;
            }
            default -> throw new SpiffingException("Unknown qualifierCode");
        }
    }
}
