package io.cridland.spiffing;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import org.bouncycastle.asn1.*;

/**
 * ESS/X.841, RFC 5912, ACP-145(A), MISSI and SSLPrivileges codecs.
 */
final class AsnCodec {
    private static final int MAX_BIT_INDEX = 16_777_215;
    private static final Map<TagType, String> OIDS = Map.of(
            TagType.restrictive, Oid.RESTRICTIVE, TagType.permissive, Oid.PERMISSIVE,
            TagType.enumeratedPermissive, Oid.ENUMERATED_PERMISSIVE,
            TagType.enumeratedRestrictive, Oid.ENUMERATED_RESTRICTIVE, TagType.informative, Oid.INFORMATIVE);

    static Wire.Value read(byte[] data, Site site, boolean clearance) {
        try {
            var root = ASN1Primitive.fromByteArray(data);
            List<ASN1Encodable> fields = clearance ? elements(ASN1Sequence.getInstance(root)) : elements(ASN1Set.getInstance(root));
            String oid = null;
            ASN1Set security = null;
            ASN1BitString bits = null;
            Lacv cls = null;
            for (var f : fields) {
                if (f instanceof ASN1ObjectIdentifier id) {
                    if (oid != null) fail("Duplicate policy identifier");
                    oid = id.getId();
                } else if (!clearance && f instanceof ASN1Integer i) {
                    if (cls != null) fail("Duplicate classification");
                    cls = new Lacv(i.getValue());
                } else if (clearance && f instanceof ASN1BitString b) {
                    if (bits != null) fail("Duplicate class list");
                    bits = b;
                } else if (f instanceof ASN1Set set) {
                    if (security != null) fail("Duplicate security categories");
                    security = set;
                } else if (!clearance && (f instanceof ASN1PrintableString || f instanceof ASN1UTF8String)) {
                    // Privacy marks do not affect the policy-driven label, as in the original library.
                } else fail("Unexpected ASN.1 label/clearance field");
            }
            if (oid == null) fail("Missing policy identifier");
            var policy = site.spif(oid);
            if (!clearance && cls == null) fail("Missing classification");
            if (clearance && (!(fields.getFirst() instanceof ASN1ObjectIdentifier)
                    || (bits != null && !(fields.get(1) instanceof ASN1BitString))))
                fail("Invalid clearance field order");
            List<Lacv> classes = clearance ? (bits == null ? List.of(new Lacv(1)) : bitValues(bits)) : List.of(cls);
            var cats = new ArrayList<Category>();
            if (security != null) for (var item : elements(security)) {
                var category = ASN1Sequence.getInstance(item);
                if (category.size() != 2) fail("Invalid security category");
                var type = ASN1TaggedObject.getInstance(category.getObjectAt(0));
                var value = ASN1TaggedObject.getInstance(category.getObjectAt(1));
                if (!type.hasContextTag(0) || !value.hasContextTag(1)) fail("Invalid security category tags");
                String syntax = ASN1ObjectIdentifier.getInstance(type, false).getId();
                var inner = value.getExplicitBaseObject();
                if (syntax.equals(Oid.MISSI) && !clearance) readMissi(inner, policy, cats, false);
                else if (syntax.equals(Oid.SSL_PRIVILEGE) && clearance) readMissi(inner, policy, cats, true);
                else {
                    TagType tagType = OIDS.entrySet().stream().filter(e -> e.getValue().equals(syntax)).map(Map.Entry::getKey)
                            .findFirst().orElseThrow(() -> new SpiffingException("Unknown security category syntax: " + syntax));
                    if (clearance && tagType == TagType.informative) fail("Informative clearance category");
                    var tag = ASN1Sequence.getInstance(inner);
                    if (tag.size() != 2) fail("Invalid ACP-145 category");
                    var ts = policy.tagSetLookup(ASN1ObjectIdentifier.getInstance(tag.getObjectAt(0)).getId());
                    addValues(ts, tagType, tag.getObjectAt(1), cats);
                }
            }
            return new Wire.Value(policy, classes, cats);
        } catch (SpiffingException e) {
            throw e;
        } catch (IOException | IllegalArgumentException | IllegalStateException | ClassCastException e) {
            throw new SpiffingException("Invalid BER/DER data", e);
        }
    }

    private static void readMissi(ASN1Encodable inner, Spif policy, List<Category> cats, boolean clearance) {
        if (!(inner instanceof ASN1Set)) fail("MISSI local RBAC policy is unsupported");
        for (var item : elements(ASN1Set.getInstance(inner))) {
            var named = ASN1Sequence.getInstance(item);
            if (named.size() != 2) fail("Invalid named tagset");
            var ts = policy.tagSetLookup(ASN1ObjectIdentifier.getInstance(named.getObjectAt(0)).getId());
            for (var tagItem : elements(ASN1Sequence.getInstance(named.getObjectAt(1)))) {
                var tag = ASN1TaggedObject.getInstance(tagItem);
                if (tag.getTagClass() != BERTags.CONTEXT_SPECIFIC) fail("Invalid MISSI tag class");
                TagType type = switch (tag.getTagNo()) {
                    case 1 -> TagType.restrictive;
                    case 6 -> TagType.permissive;
                    case 2 -> enumeratedType(ts);
                    case 7 -> TagType.informative;
                    default -> throw new SpiffingException("Unknown MISSI tag");
                };
                ASN1Encodable values;
                if (clearance) {
                    if (type == TagType.informative) throw new SpiffingException("Informative SSL privilege");
                    values = tag.getTagNo() == 2 ? ASN1Set.getInstance(tag, false) : ASN1BitString.getInstance(tag, false);
                } else if (type == TagType.informative) values = tag.getExplicitBaseObject();
                else {
                    var seq = ASN1Sequence.getInstance(tag, false);
                    if (seq.size() < 1 || seq.size() > 2) fail("Invalid MISSI attributes");
                    if (seq.size() == 2) ASN1Integer.getInstance(seq.getObjectAt(0));
                    values = seq.getObjectAt(seq.size() - 1);
                }
                addValues(ts, type, values, cats);
            }
        }
    }

    private static TagType enumeratedType(TagSet ts) {
        boolean perm = !ts.categories(TagType.enumeratedPermissive).isEmpty();
        boolean rest = !ts.categories(TagType.enumeratedRestrictive).isEmpty();
        if (perm && rest) fail("MISSI cannot distinguish both enumerated types in one tagset");
        return perm ? TagType.enumeratedPermissive : TagType.enumeratedRestrictive;
    }

    private static void addValues(TagSet ts, TagType type, ASN1Encodable values, List<Category> cats) {
        boolean bitmap = type == TagType.restrictive || type == TagType.permissive || (type == TagType.informative && values instanceof ASN1BitString);
        List<Lacv> lacvs;
        if (bitmap) lacvs = bitValues(ASN1BitString.getInstance(values));
        else
            lacvs = elements(ASN1Set.getInstance(values)).stream().map(v -> new Lacv(ASN1Integer.getInstance(v).getValue())).toList();
        for (var lacv : lacvs) {
            var cat = ts.categoryLookup(type, lacv);
            if (type == TagType.informative && cat.tag().informativeBitSet() != bitmap)
                fail("Informative encoding differs from policy");
            cats.add(cat);
        }
    }

    private static List<Lacv> bitValues(ASN1BitString bits) {
        byte[] data = bits.getBytes();
        var out = new ArrayList<Lacv>();
        long count = (long) data.length * 8 - bits.getPadBits();
        if (count > MAX_BIT_INDEX + 1L) fail("Bitmap exceeds supported size");
        for (int i = 0; i < count; i++) if ((data[i / 8] & (0x80 >>> (i % 8))) != 0) out.add(new Lacv(i));
        return out;
    }

    static byte[] write(Spif policy, Collection<Lacv> classes, Set<Category> cats, boolean clearance) {
        var fields = new ASN1EncodableVector();
        fields.add(new ASN1ObjectIdentifier(policy.policyId()));
        if (clearance) {
            // RFC 5912 DEFAULT {unclassified}; explicitly encode every other list, including empty.
            if (!(classes.size() == 1 && classes.contains(new Lacv(1)))) fields.add(bits(classes));
        } else fields.add(new ASN1Integer(classes.iterator().next().value()));
        if (!cats.isEmpty()) fields.add(securityCategories(policy, cats, clearance));
        try {
            return (clearance ? new DERSequence(fields) : new DERSet(fields)).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new SpiffingException("Cannot encode DER", e);
        }
    }

    private record Group(TagSet ts, TagType type, boolean bitmap) {
    }

    private static Map<Group, List<Category>> groups(Set<Category> cats) {
        Map<Group, List<Category>> groups = new LinkedHashMap<>();
        for (var c : cats) {
            var type = c.tag().type();
            boolean bitmap = type == TagType.restrictive || type == TagType.permissive || (type == TagType.informative && c.tag().informativeBitSet());
            groups.computeIfAbsent(new Group(c.tag().tagSet(), type, bitmap), k -> new ArrayList<>()).add(c);
        }
        return groups;
    }

    private static ASN1Set securityCategories(Spif policy, Set<Category> cats, boolean clearance) {
        String syntax = clearance ? policy.privilegeId() : policy.rbacId();
        var result = new ASN1EncodableVector();
        var groups = groups(cats);
        if (syntax.equals(Oid.NATO)) {
            for (var entry : groups.entrySet()) {
                var group = entry.getKey();
                var tag = new DERSequence(new ASN1Encodable[]{new ASN1ObjectIdentifier(group.ts.id()), attributes(group, entry.getValue())});
                result.add(category(OIDS.get(group.type), tag));
            }
        } else if (syntax.equals(clearance ? Oid.SSL_PRIVILEGE : Oid.MISSI)) {
            Map<TagSet, ASN1EncodableVector> named = new LinkedHashMap<>();
            for (var entry : groups.entrySet()) {
                var group = entry.getKey();
                if (group.type == TagType.enumeratedPermissive || group.type == TagType.enumeratedRestrictive)
                    enumeratedType(group.ts);
                int tagNo = switch (group.type) {
                    case restrictive -> 1;
                    case permissive -> 6;
                    case enumeratedPermissive, enumeratedRestrictive -> 2;
                    case informative -> 7;
                };
                var values = attributes(group, entry.getValue());
                ASN1Encodable tag;
                if (clearance) tag = new DERTaggedObject(false, tagNo, values);
                else if (tagNo == 7) tag = new DERTaggedObject(true, 7, values);
                else tag = new DERTaggedObject(false, tagNo, new DERSequence(values));
                named.computeIfAbsent(group.ts, k -> new ASN1EncodableVector()).add(tag);
            }
            var sets = new ASN1EncodableVector();
            for (var entry : named.entrySet())
                sets.add(new DERSequence(new ASN1Encodable[]{new ASN1ObjectIdentifier(entry.getKey().id()), new DERSequence(entry.getValue())}));
            result.add(category(syntax, new DERSet(sets)));
        } else throw new SpiffingException("Unsupported category syntax: " + syntax);
        return new DERSet(result);
    }

    private static ASN1Sequence category(String oid, ASN1Encodable value) {
        return new DERSequence(new ASN1Encodable[]{new DERTaggedObject(false, 0, new ASN1ObjectIdentifier(oid)), new DERTaggedObject(true, 1, value)});
    }

    private static ASN1Encodable attributes(Group group, List<Category> categories) {
        if (group.bitmap) return bits(categories.stream().map(Category::lacv).toList());
        var values = new ASN1EncodableVector();
        for (var c : categories) values.add(new ASN1Integer(c.lacv().value()));
        return new DERSet(values);
    }

    private static ASN1BitString bits(Collection<Lacv> lacvs) {
        int max = -1;
        for (var l : lacvs) {
            if (l.value().compareTo(BigInteger.valueOf(MAX_BIT_INDEX)) > 0) fail("Bitmap LACV exceeds supported size");
            max = Math.max(max, l.value().intValueExact());
        }
        byte[] data = new byte[max < 0 ? 0 : max / 8 + 1];
        for (var l : lacvs) {
            int i = l.value().intValueExact();
            data[i / 8] |= (byte) (0x80 >>> (i % 8));
        }
        return new DERBitString(data, max < 0 ? 0 : 7 - max % 8);
    }

    private static List<ASN1Encodable> elements(ASN1Sequence seq) {
        return Arrays.asList(seq.toArray());
    }

    private static List<ASN1Encodable> elements(ASN1Set set) {
        return Arrays.asList(set.toArray());
    }

    private static void fail(String message) {
        throw new SpiffingException(message);
    }
}
