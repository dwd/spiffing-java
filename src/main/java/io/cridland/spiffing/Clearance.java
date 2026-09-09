package io.cridland.spiffing;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * A clearance grants explicit classifications; hierarchy does not imply access.
 */
public final class Clearance {
    private final Spif policy;
    private final SortedSet<Lacv> classifications = new TreeSet<>();
    private final SortedSet<Category> categories = new TreeSet<>(Comparator.comparingInt(c -> c.ordinal));

    public Clearance(Spif policy) {
        this.policy = Objects.requireNonNull(policy);
    }

    public static Clearance parse(byte[] data, Format format, Site site) {
        return Wire.parseClearance(data, format, site);
    }

    public static Clearance parse(byte[] data, Format format) {
        return parse(data, format, Site.site());
    }

    public static Clearance parse(String xml, Site site) {
        return parse(xml.getBytes(StandardCharsets.UTF_8), Format.XML, site);
    }

    public Spif policy() {
        return policy;
    }

    public String policyId() {
        return policy.policyId();
    }

    public Set<Lacv> classifications() {
        return Collections.unmodifiableSortedSet(classifications);
    }

    public Set<Category> categories() {
        return Collections.unmodifiableSortedSet(categories);
    }

    public boolean hasClassification(long lacv) {
        return hasClassification(new Lacv(lacv));
    }

    public boolean hasClassification(Lacv lacv) {
        return classifications.contains(lacv);
    }

    public boolean hasCategory(Category c) {
        return c.tag().tagSet().policy == policy && categories.contains(c);
    }

    public boolean hasCategory(Collection<Category> cs) {
        return cs.stream().anyMatch(this::hasCategory);
    }

    public Clearance addClassification(long lacv) {
        return addClassification(new Lacv(lacv));
    }

    public Clearance addClassification(Lacv lacv) {
        policy.classificationLookup(lacv);
        classifications.add(lacv);
        return this;
    }

    public Clearance addCategory(Category c) {
        policy.checkPolicy(c.tag().tagSet().policy);
        if (c.tag().type() == TagType.informative)
            throw new SpiffingException("Informative categories are not clearance privileges");
        categories.add(c);
        return this;
    }

    public byte[] write(Format format) {
        return Wire.write(policy, classifications, categories, true, format);
    }
}
