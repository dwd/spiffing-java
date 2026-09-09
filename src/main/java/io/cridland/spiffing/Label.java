package io.cridland.spiffing;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * A label with one classification and a set of policy-owned categories.
 */
public final class Label {
    private final Spif policy;
    private final Classification classification;
    private final SortedSet<Category> categories = new TreeSet<>(Comparator.comparingInt(c -> c.ordinal));

    public Label(Spif policy, long classification) {
        this(policy, new Lacv(classification));
    }

    public Label(Spif policy, Lacv classification) {
        this.policy = Objects.requireNonNull(policy);
        this.classification = policy.classificationLookup(classification);
    }

    public static Label parse(byte[] data, Format format, Site site) {
        return Wire.parseLabel(data, format, site);
    }

    public static Label parse(byte[] data, Format format) {
        return parse(data, format, Site.site());
    }

    public static Label parse(String xml, Site site) {
        return parse(xml.getBytes(StandardCharsets.UTF_8), Format.XML, site);
    }

    public Spif policy() {
        return policy;
    }

    public String policyId() {
        return policy.policyId();
    }

    public Classification classification() {
        return classification;
    }

    public Set<Category> categories() {
        return Collections.unmodifiableSortedSet(categories);
    }

    public boolean hasCategory(Category c) {
        return c.tag().tagSet().policy == policy && categories.contains(c);
    }

    public Label addCategory(Category c) {
        policy.checkPolicy(c.tag().tagSet().policy);
        categories.add(c);
        return this;
    }

    public byte[] write(Format format) {
        return Wire.write(policy, List.of(classification.lacv()), categories, false, format);
    }

    /**
     * Policy equivalence translation; this performs no cryptographic encryption.
     */
    public Label encrypt(String policyId, Site site) {
        return policy.translate(this, policyId, site);
    }

    public Label encrypt(String policyId) {
        return encrypt(policyId, Site.site());
    }
}
