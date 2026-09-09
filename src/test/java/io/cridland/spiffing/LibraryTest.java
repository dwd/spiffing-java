package io.cridland.spiffing;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.junit.jupiter.api.Test;
import org.bouncycastle.asn1.*;

import static org.junit.jupiter.api.Assertions.*;

class LibraryTest {
    static final String SIMPLE = """
            <SPIF><securityPolicyId name="Example" id="1.2.3"/>
            <securityClassifications>
              <securityClassification name="Unmarked" lacv="0" hierarchy="0"/>
              <securityClassification name="Public" lacv="1" hierarchy="1"/>
              <securityClassification name="Secret" lacv="4" hierarchy="2"/>
            </securityClassifications></SPIF>
            """;
    static final String TAGS = """
            <securityCategoryTagSets><securityCategoryTagSet name="Attributes" id="1.2.3.1">
            <securityCategoryTag name="Required" tagType="restrictive"><tagCategory name="R" lacv="8"/></securityCategoryTag>
            <securityCategoryTag name="Release" tagType="permissive"><tagCategory name="A" lacv="1"/><tagCategory name="B" lacv="2"/></securityCategoryTag>
            <securityCategoryTag name="Enum" tagType="enumerated" enumType="permissive"><tagCategory name="Large" lacv="184467440737095516160"/></securityCategoryTag>
            <securityCategoryTag name="Info" tagType="tagType7" tag7Encoding="securityAttributes"><tagCategory name="I" lacv="23"/></securityCategoryTag>
            </securityCategoryTagSet></securityCategoryTagSets>
            """;

    static Site simple() {
        var site = new Site();
        site.load(SIMPLE);
        return site;
    }

    static Site withTags() {
        var site = new Site();
        site.load(SIMPLE.replace("</SPIF>", TAGS + "</SPIF>"));
        return site;
    }

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    @Test
    void knownEssDerAndIndefiniteBer() {
        var site = simple();
        var expected = hex("310702010106022a03");
        var label = site.label(expected, Format.DER);
        assertEquals(new Lacv(1), label.classification().lacv());
        assertArrayEquals(expected, label.write(Format.DER));
        var ber = site.label(hex("318006022a030201010000"), Format.BER);
        assertSame(label.classification(), ber.classification());
        assertArrayEquals(expected, ber.write(Format.BER));
    }

    @Test
    void knownAcp145RestrictiveBitmap() {
        var site = withTags();
        // ESS SET, INTEGER 1, policy 1.2.3, category syntax ACP restrictive,
        // tagset 1.2.3.1, BIT STRING with bit 8 set and seven pad bits.
        byte[] der = hex("312502010106022a03311c301a800a60864801650201080300a10c300a06032a03010303070080");
        var label = site.label(der, Format.DER);
        assertEquals(Set.of(site.spif("1.2.3").tagSetLookup("1.2.3.1").categoryLookup(TagType.restrictive, 8)), label.categories());
        assertArrayEquals(der, label.write(Format.DER));
    }

    @Test
    void knownClearanceDefaultAndExplicitEmpty() {
        var site = simple();
        var c = site.clearance(hex("300406022a03"), Format.BER);
        assertThrows(SpiffingException.class, () -> site.clearance(hex("300a0302004006022a03"), Format.BER));
        assertTrue(c.hasClassification(1));
        assertFalse(c.hasClassification(0));
        assertArrayEquals(hex("300406022a03"), c.write(Format.DER));
        var empty = site.clearance(hex("300706022a03030100"), Format.DER);
        assertTrue(empty.classifications().isEmpty());
        assertArrayEquals(hex("300706022a03030100"), empty.write(Format.DER));
        assertFalse(c.policy().acdf(new Label(c.policy(), 4), c));
    }

    @Test
    void missiAndSslPrivileges() throws Exception {
        var site = UpstreamTest.site("food-policy-missi.xml");
        var label = site.label(UpstreamTest.data("food-label-milk-chocolate.xml"), Format.XML);
        var plastic = label.policy().tagSetLookupByName("Packaging").categoryLookup(TagType.informative, 0);
        label.addCategory(plastic);
        UpstreamTest.roundTrip(label, site);
        var c = site.clearance(UpstreamTest.data("food-clearance-all-okay.xml"), Format.XML);
        var copy = site.clearance(c.write(Format.DER), Format.BER);
        assertEquals(c.categories(), copy.categories());
        assertEquals(c.classifications(), copy.classifications());
        assertTrue(c.policy().acdf(label, copy));
        var denied = site.clearance(UpstreamTest.data("food-clearance-lactose-intolerant.xml"), Format.XML);
        assertFalse(label.policy().acdf(label, site.clearance(denied.write(Format.BER), Format.ANY)));
    }

    @Test
    void arbitraryPrecisionEnumerationsAndInformativeSets() {
        var site = withTags();
        var p = site.spif("1.2.3");
        var ts = p.tagSetLookup("1.2.3.1");
        var big = Lacv.parse("184467440737095516160");
        assertEquals(new BigInteger("184467440737095516160"), big.value());
        var label = new Label(p, 1).addCategory(ts.categoryLookup(TagType.enumeratedPermissive, big)).addCategory(ts.categoryLookup(TagType.informative, 23));
        UpstreamTest.roundTrip(label, site);
        var clearance = new Clearance(p).addClassification(1).addCategory(ts.categoryLookup(TagType.enumeratedPermissive, big));
        assertTrue(p.acdf(label, site.clearance(clearance.write(Format.DER), Format.BER)));
        assertThrows(SpiffingException.class, () -> Lacv.parse("-1"));
    }

    @Test
    void permissiveAccessIsPerTagAndRestrictiveRequiresAll() throws Exception {
        var site = UpstreamTest.site("food-policy.xml");
        var p = site.spif("1.2.826.0.1.6726289.0.0");
        var taste = p.tagSetLookupByName("Taste Sensations");
        var crunchy = taste.categoryLookup(TagType.permissive, 0);
        var sweet = taste.categoryLookup(TagType.permissive, 3);
        var salty = taste.categoryLookup(TagType.permissive, 4);
        var milk = p.tagSetLookupByName("Allergens").categoryLookup(TagType.restrictive, 1);
        var label = new Label(p, 51).addCategory(crunchy).addCategory(sweet).addCategory(salty).addCategory(milk);
        var c = new Clearance(p).addClassification(51).addCategory(crunchy).addCategory(milk);
        assertFalse(p.acdf(label, c));
        c.addCategory(salty);
        assertTrue(p.acdf(label, c));
        assertFalse(p.acdf(label, new Clearance(p).addClassification(51).addCategory(crunchy).addCategory(sweet)));
    }

    @Test
    void registryIsolationAndUnmodifiableViews() {
        var a = withTags();
        var b = withTags();
        var p = a.spif("1.2.3");
        var q = b.spif("1.2.3");
        var label = new Label(p, 1);
        var other = q.tagSetLookup("1.2.3.1").categoryLookup(TagType.restrictive, 8);
        assertThrows(SpiffingException.class, () -> label.addCategory(other));
        assertFalse(label.hasCategory(other));
        assertThrows(SpiffingException.class, () -> p.acdf(label, new Clearance(q).addClassification(1)));
        assertThrows(SpiffingException.class, () -> q.valid(label));
        assertThrows(UnsupportedOperationException.class, () -> label.categories().clear());
        assertThrows(SpiffingException.class, () -> a.load(SIMPLE));
        assertSame(p, a.spif("1.2.3"));
    }

    @Test
    void malformedXmlAndExternalEntitiesAreRejected() {
        var site = simple();
        assertThrows(SpiffingException.class, () -> site.label("<label>"));
        assertThrows(SpiffingException.class, () -> site.label("<!DOCTYPE label [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><label>&x;</label>"));
        assertThrows(SpiffingException.class, () -> site.label("<label xmlns='http://surevine.com/xmlns/spiffy'><policy id='1.2.3'/></label>"));
        assertThrows(SpiffingException.class, () -> site.label("<label xmlns='wrong'><policy id='1.2.3'/><classification lacv='1'/></label>"));
        assertThrows(SpiffingException.class, () -> site.label("<label xmlns='http://surevine.com/xmlns/spiffy'><policy id='1.2.3'/><classification lacv='1'/><classification lacv='4'/></label>"));
    }

    @Test
    void prefixedXmlAndBomDetection() {
        var site = simple();
        String xml = "<s:label xmlns:s='http://surevine.com/xmlns/spiffy'><s:policy id='1.2.3'/><s:classification lacv='1'/></s:label>";
        assertEquals(new Lacv(1), site.label(xml).classification().lacv());
        assertEquals(new Lacv(1), site.label(("\ufeff" + xml).getBytes(StandardCharsets.UTF_8), Format.ANY).classification().lacv());
        assertEquals(new Lacv(1), site.label(xml.getBytes(StandardCharsets.UTF_16), Format.ANY).classification().lacv());
    }

    @Test
    void natoPolicyMismatchAndExplicitFormats() {
        var site = simple();
        var label = new Label(site.spif("1.2.3"), 1);
        var nato = new String(label.write(Format.NATO), StandardCharsets.UTF_8);
        assertThrows(SpiffingException.class, () -> site.label(nato.replace("urn:oid:1.2.3", "urn:oid:1.2.4")));
        assertThrows(SpiffingException.class, () -> site.label(label.write(Format.XML), Format.NATO));
        assertThrows(SpiffingException.class, () -> label.write(Format.ANY));
        assertThrows(SpiffingException.class, () -> site.label(new byte[0], Format.ANY));
    }

    @Test
    void truncatedBerTrailingDataAndUnknownCategoriesAreRejected() throws Exception {
        var site = simple();
        for (String bad : List.of("31", "310702010106022a", "310702010106022a0300", "310a02010102010406022a03", "310406022a03"))
            assertThrows(SpiffingException.class, () -> site.label(hex(bad), Format.BER));
        var category = new DERSequence(new ASN1Encodable[]{new DERTaggedObject(false, 0, new ASN1ObjectIdentifier("1.2.999")), new DERTaggedObject(true, 1, new DERSequence())});
        var label = new DERSet(new ASN1Encodable[]{new ASN1Integer(1), new ASN1ObjectIdentifier("1.2.3"), new DERSet(category)}).getEncoded();
        assertThrows(SpiffingException.class, () -> site.label(label, Format.BER));
    }

    @Test
    void malformedPolicyConstraintsAreRejected() {
        assertThrows(SpiffingException.class, () -> new Spif(SIMPLE.replace("lacv=\"4\"", "lacv=\"1\"")));
        assertThrows(SpiffingException.class, () -> new Spif(SIMPLE.replace("</SPIF>", TAGS.replace("tagType=\"restrictive\"", "tagType=\"unknown\"") + "</SPIF>")));
        var required = "<requiredCategory operation='all'><categoryGroup tagSetRef='Missing' tagType='permissive'/></requiredCategory>";
        assertThrows(SpiffingException.class, () -> new Spif(SIMPLE.replace("name=\"Public\" lacv=\"1\" hierarchy=\"1\"/>", "name=\"Public\" lacv=\"1\" hierarchy=\"1\">" + required + "</securityClassification>")));
    }

    @Test
    void onlyOneAndAllConstraintSemantics() {
        for (String op : List.of("onlyOne", "all", "oneOrMore")) {
            var rule = "<requiredCategory operation='" + op + "'><categoryGroup tagSetRef='Attributes' tagType='permissive' lacv='1'/><categoryGroup tagSetRef='Attributes' tagType='permissive' lacv='2'/></requiredCategory>";
            var xml = SIMPLE.replace("name=\"Public\" lacv=\"1\" hierarchy=\"1\"/>", "name=\"Public\" lacv=\"1\" hierarchy=\"1\">" + rule + "</securityClassification>").replace("</SPIF>", TAGS + "</SPIF>");
            var p = new Spif(xml);
            var ts = p.tagSetLookup("1.2.3.1");
            var label = new Label(p, 1);
            assertFalse(p.valid(label));
            assertThrows(SpiffingException.class, () -> p.assertValid(label));
            label.addCategory(ts.categoryLookup(TagType.permissive, 1));
            assertEquals(!op.equals("all"), p.valid(label));
            label.addCategory(ts.categoryLookup(TagType.permissive, 2));
            assertEquals(!op.equals("onlyOne"), p.valid(label));
        }
    }

    @Test
    void markingLocationAndLanguageFallback() {
        var xml = SIMPLE.replace("name=\"Public\" lacv=\"1\" hierarchy=\"1\"/>", """
                name="Public" lacv="1" hierarchy="1">
                  <markingData phrase="TOP"><code>pageTop</code></markingData>
                  <markingData phrase="BAS" xml:lang="fr"><code>pageBottom</code></markingData>
                </securityClassification>
                """);
        var p = new Spif(xml);
        var label = new Label(p, 1);
        assertEquals("Example TOP", p.displayMarking(label, MarkingCode.pageTop));
        assertEquals("Example Public", p.displayMarking(label));
        assertEquals("Example BAS", p.displayMarking(label, "fr-CA"));
        assertEquals("Example Public", p.displayMarking(label, "de"));
    }

    @Test
    void missingEquivalenceFailsWithoutMutatingSource() throws Exception {
        var site = UpstreamTest.site("tlp-plus.xml", "tlp.xml");
        var label = site.label(UpstreamTest.data("tlpx-amber-eu.xml"), Format.XML);
        byte[] original = label.write(Format.DER);
        assertThrows(SpiffingException.class, () -> label.encrypt("1.2.3", site));
        assertArrayEquals(original, label.write(Format.DER));
        assertNotEquals(label.policyId(), label.encrypt("1.2.826.0.1.6726289.0.2", site).policyId());
        assertArrayEquals(original, label.write(Format.DER));
    }
}
