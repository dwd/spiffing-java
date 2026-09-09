package io.cridland.spiffing;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.w3c.dom.Element;

/**
 * An Open XML SPIF policy, including validation, markings and equivalence rules.
 */
public final class Spif {
    private final String id, name, rbacId, privilegeId;
    private final Map<Lacv, Classification> classes = new TreeMap<>();
    private final Map<String, Classification> classNames = new LinkedHashMap<>();
    private final Map<String, TagSet> tagSets = new LinkedHashMap<>(), tagSetNames = new LinkedHashMap<>();
    private final Map<String, String> equivalents = new LinkedHashMap<>();
    private final Map<String, Element> equivalentRules = new LinkedHashMap<>();
    private final Markings markings;

    public Spif(String xml) {
        this(xml.getBytes(StandardCharsets.UTF_8));
    }

    public Spif(InputStream in) throws IOException {
        this(in.readAllBytes());
    }

    public Spif(byte[] xml) {
        var root = Xml.parse(xml);
        if (!root.getLocalName().equals("SPIF")) throw new SpiffingException("Not a spif");
        if (root.getNamespaceURI() != null && !root.getNamespaceURI().equals("http://www.xmlspif.org/spif"))
            throw new SpiffingException("Unknown SPIF namespace");
        var ident = Xml.child(root, "securityPolicyId");
        id = Xml.required(ident, "id");
        name = Xml.required(ident, "name");
        new org.bouncycastle.asn1.ASN1ObjectIdentifier(id);
        rbacId = Xml.attr(root, "rbacId", Oid.NATO);
        privilegeId = Xml.attr(root, "privilegeId", Oid.NATO);
        markings = Markings.parse(root);
        for (var e : Xml.children(Xml.optional(root, "equivalentPolicies"), "equivalentPolicy")) {
            String eid = Xml.required(e, "id");
            unique(equivalents, Xml.required(e, "name"), eid, "equivalent policy");
            unique(equivalentRules, eid, e, "equivalent policy id");
        }
        for (var e : Xml.children(Xml.child(root, "securityClassifications"), "securityClassification")) {
            var c = new Classification(e);
            unique(classes, c.lacv(), c, "classification");
            unique(classNames, c.name(), c, "classification name");
        }
        if (classes.isEmpty()) throw new SpiffingException("No classifications");
        int ordinal = 0;
        for (var e : Xml.children(Xml.optional(root, "securityCategoryTagSets"), "securityCategoryTagSet")) {
            var ts = new TagSet(this, e);
            new org.bouncycastle.asn1.ASN1ObjectIdentifier(ts.id());
            unique(tagSets, ts.id(), ts, "TagSet id");
            unique(tagSetNames, ts.name(), ts, "TagSet name");
            var keys = new HashSet<String>();
            var names = new HashSet<String>();
            var tagNames = new HashSet<String>();
            for (var te : Xml.children(e, "securityCategoryTag")) {
                var t = new Tag(ts, te);
                if (!tagNames.add(t.name())) throw new SpiffingException("Duplicate tag name");
                ts.tags.add(t);
                for (var ce : Xml.children(te, "tagCategory")) {
                    var c = new Category(t, ce, ordinal++);
                    if (!keys.add(t.type() + ":" + c.lacv())) throw new SpiffingException("Duplicate category LACV");
                    if (!names.add(t.type().normalized() + ":" + c.name()))
                        throw new SpiffingException("Duplicate category name");
                    t.categories.add(c);
                }
            }
        }
        for (var c : classes.values()) {
            checkRules(c.source);
            checkEquivalents(c.source, "equivalentClassification");
        }
        for (var ts : tagSets.values())
            for (var t : ts.tags)
                for (var c : t.categories) {
                    checkRules(c.source);
                    checkEquivalents(c.source, "equivalentSecCategoryTag");
                    var excluded = new HashSet<String>();
                    for (var e : Xml.children(c.source, "excludedClass")) {
                        classificationLookup(e.getTextContent());
                        if (!excluded.add(e.getTextContent()))
                            throw new SpiffingException("Duplicate excluded classification in category");
                    }
                }
    }

    private static <K, V> void unique(Map<K, V> map, K key, V value, String kind) {
        if (map.putIfAbsent(key, value) != null) throw new SpiffingException("Duplicate " + kind + " " + key);
    }

    private void checkEquivalents(Element holder, String kind) {
        for (var e : Xml.children(holder, kind)) {
            equivalentId(e);
            if (kind.equals("equivalentClassification")) {
                Lacv.parse(Xml.required(e, "lacv"));
                if (!Set.of("encrypt", "decrypt", "both").contains(Xml.required(e, "applied")))
                    throw new SpiffingException("Unknown equivalence application");
            } else if (!e.hasAttribute("action")) {
                Xml.required(e, "tagSetId");
                TagType.policy(e);
                Lacv.parse(Xml.required(e, "lacv"));
            }
        }
    }

    private void checkRules(Element holder) {
        for (var e : Xml.children(holder, "excludedCategory")) resolve(e);
        for (var g : Xml.children(holder, "requiredCategory")) {
            operation(g);
            for (var e : Xml.children(g, "categoryGroup")) resolve(e);
        }
    }

    private String operation(Element e) {
        String op = Xml.required(e, "operation");
        if (!Set.of("onlyOne", "oneOrMore", "all").contains(op))
            throw new SpiffingException("Unknown category operation: " + op);
        return op;
    }

    private List<Category> resolve(Element e) {
        var ts = tagSetLookupByName(Xml.required(e, "tagSetRef"));
        var type = TagType.policy(e);
        return e.hasAttribute("lacv") ? List.of(ts.categoryLookup(type, Lacv.parse(e.getAttribute("lacv")))) : ts.categories(type);
    }

    private boolean matches(Element e, Label label) {
        return resolve(e).stream().anyMatch(label::hasCategory);
    }

    private boolean rulesValid(Element e, Label label) {
        for (var ex : Xml.children(e, "excludedClass"))
            if (ex.getTextContent().equals(label.classification().name())) return false;
        for (var ex : Xml.children(e, "excludedCategory")) if (matches(ex, label)) return false;
        for (var group : Xml.children(e, "requiredCategory")) {
            var members = Xml.children(group, "categoryGroup");
            long count = members.stream().filter(m -> matches(m, label)).count();
            boolean pass = switch (operation(group)) {
                case "onlyOne" -> count == 1;
                case "oneOrMore" -> count > 0;
                default -> count > 0 && count == members.size();
            };
            if (!pass) return false;
        }
        return true;
    }

    public String policyId() {
        return id;
    }

    public String name() {
        return name;
    }

    public String rbacId() {
        return rbacId;
    }

    public String privilegeId() {
        return privilegeId;
    }

    public Collection<Classification> classifications() {
        return List.copyOf(classes.values());
    }

    public Collection<TagSet> tagSets() {
        return List.copyOf(tagSets.values());
    }

    public Classification classificationLookup(long lacv) {
        return classificationLookup(new Lacv(lacv));
    }

    public Classification classificationLookup(Lacv lacv) {
        var c = classes.get(lacv);
        if (c == null) throw new SpiffingException("Unknown classification: " + lacv);
        return c;
    }

    public Classification classificationLookup(String name) {
        var c = classNames.get(name);
        if (c == null) throw new SpiffingException("Unknown classification: " + name);
        return c;
    }

    public TagSet tagSetLookup(String id) {
        var ts = tagSets.get(id);
        if (ts == null) throw new SpiffingException("Unknown tagset id: " + id);
        return ts;
    }

    public TagSet tagSetLookupByName(String name) {
        var ts = tagSetNames.get(name);
        if (ts == null) throw new SpiffingException("Unknown tagset name: " + name);
        return ts;
    }

    void checkPolicy(Spif policy) {
        if (policy != this) throw new SpiffingException("Policy mismatch: " + policy.policyId());
    }

    public boolean valid(Label label) {
        checkPolicy(label.policy());
        return rulesValid(label.classification().source, label) && label.categories().stream().allMatch(c -> rulesValid(c.source, label));
    }

    public void assertValid(Label label) {
        if (!valid(label)) throw new SpiffingException("Label violates policy constraints");
    }

    /**
     * Evaluates classification membership and category access; validation is a separate operation.
     */
    public boolean acdf(Label label, Clearance clearance) {
        checkPolicy(label.policy());
        checkPolicy(clearance.policy());
        if (!clearance.hasClassification(label.classification().lacv())) return false;
        Map<Tag, List<Category>> permissive = new LinkedHashMap<>();
        for (var c : label.categories()) {
            if (c.tag().type().isRestrictive() && !clearance.hasCategory(c)) return false;
            if (c.tag().type().isPermissive()) permissive.computeIfAbsent(c.tag(), k -> new ArrayList<>()).add(c);
        }
        return permissive.values().stream().allMatch(cs -> cs.stream().anyMatch(clearance::hasCategory));
    }

    private String equivalentId(Element e) {
        String ref = Xml.required(e, "policyRef");
        var eid = equivalents.get(ref);
        if (eid == null) throw new SpiffingException("PolicyRef not found: " + ref);
        return eid;
    }

    private static void fixup(Element holder, Label label) {
        for (var g : Xml.children(holder, "requiredCategory"))
            for (var cd : Xml.children(g, "categoryGroup"))
                for (var c : label.policy().resolve(cd)) label.addCategory(c);
    }

    Label translate(Label old, String targetId, Site site) {
        checkPolicy(old.policy());
        var mappings = Xml.children(old.classification().source, "equivalentClassification").stream()
                .filter(e -> equivalentId(e).equals(targetId) && Set.of("encrypt", "both").contains(e.getAttribute("applied"))).toList();
        if (mappings.size() != 1) throw new SpiffingException("No unique equivalent classification");
        var mapping = mappings.get(0);
        var label = new Label(site.spif(targetId), Lacv.parse(Xml.required(mapping, "lacv")));
        fixup(mapping, label);
        for (var c : old.categories()) {
            var equiv = Xml.children(c.source, "equivalentSecCategoryTag").stream().filter(e -> equivalentId(e).equals(targetId)).toList();
            if (equiv.isEmpty()) throw new SpiffingException("No equivalence to " + c.name());
            for (var e : equiv)
                if (!e.hasAttribute("action"))
                    label.addCategory(label.policy().tagSetLookup(Xml.required(e, "tagSetId")).categoryLookup(TagType.policy(e), Lacv.parse(Xml.required(e, "lacv"))));
        }
        fixup(equivalentRules.get(targetId), label);
        return label;
    }

    public String displayMarking(Label label) {
        return displayMarking(label, "", MarkingCode.pageBottom);
    }

    public String displayMarking(Label label, String language) {
        return displayMarking(label, language, MarkingCode.pageBottom);
    }

    public String displayMarking(Label label, MarkingCode location) {
        return displayMarking(label, "", location);
    }

    public String displayMarking(Label label, String language, MarkingCode location) {
        checkPolicy(label.policy());
        var pm = markings.get(language);
        var cm = label.classification().markings.get(language);
        String sep = pm == null || pm.separator.isEmpty() ? " " : pm.separator;
        String policyName = name;
        if (pm != null && pm.flag(location, MarkingCode.replacePolicy)) policyName = pm.policyPhrase(location, name);
        else if (cm != null && cm.flag(location, MarkingCode.replacePolicy))
            policyName = cm.policyPhrase(location, label.classification().name());
        else for (var c : label.categories()) {
                var m = c.markings.get(language);
                if (m != null && m.flag(location, MarkingCode.replacePolicy)) {
                    policyName = m.policyPhrase(location, c.name());
                    break;
                }
            }
        var out = new StringBuilder(policyName);
        boolean suppress = label.categories().stream().anyMatch(c -> {
            var m = c.markings.get(language);
            return m != null && m.flag(location, MarkingCode.suppressClassName);
        });
        if (!suppress) {
            if (!out.isEmpty()) out.append(sep);
            var m = cm == null ? pm : cm;
            out.append(m == null ? label.classification().name() : m.phrase(location, label.classification().name()));
        }
        categoryMarkings(out, label.categories(), language, location, sep);
        return pm == null ? out.toString() : pm.prefix + out + pm.suffix;
    }

    public String displayMarking(Clearance clearance) {
        return displayMarking(clearance, "");
    }

    public String displayMarking(Clearance clearance, String language) {
        checkPolicy(clearance.policy());
        var pm = markings.get(language);
        String sep = pm == null || pm.separator.isEmpty() ? " " : pm.separator;
        var out = new StringBuilder(pm == null ? "" : pm.prefix).append('{');
        var names = clearance.classifications().stream().map(this::classificationLookup)
                .sorted(Comparator.comparingLong(Classification::hierarchy).thenComparing(Classification::lacv)).map(Classification::name).toList();
        out.append(names.isEmpty() ? (classes.containsKey(new Lacv(0)) ? classes.get(new Lacv(0)).name() : "unclassified (auto)") : String.join("|", names));
        out.append('}');
        categoryMarkings(out, clearance.categories(), language, MarkingCode.pageBottom, sep);
        if (pm != null) out.append(pm.suffix);
        return out.toString();
    }

    private static void categoryMarkings(StringBuilder out, Set<Category> categories, String language, MarkingCode loc, String sep) {
        Tag current = null;
        String suffix = "", tagSep = "/";
        for (var c : categories) {
            var m = c.markings.get(language);
            if (m == null) m = c.tag().markings.get(language);
            String phrase = m == null ? c.name() : m.phrase(loc, c.name());
            if (phrase.isEmpty()) continue;
            if (current != c.tag()) {
                current = c.tag();
                out.append(suffix);
                if (!out.isEmpty()) out.append(sep);
                m = current.markings.get(language);
                suffix = m == null ? "" : m.suffix;
                tagSep = m == null || m.separator.isEmpty() ? "/" : m.separator;
                if (m != null) out.append(m.prefix);
            } else out.append(tagSep);
            out.append(phrase);
        }
        out.append(suffix);
    }
}
