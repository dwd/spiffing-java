package io.cridland.spiffing;

import org.junit.jupiter.api.*;
import org.w3c.dom.Element;

import java.io.*;
import java.util.*;
import java.util.stream.*;

import static org.junit.jupiter.api.Assertions.*;

class UpstreamTest {
    static byte[] data(String name) throws IOException {
        try (var in = UpstreamTest.class.getResourceAsStream("/test-data/" + name)) {
            return in == null ? new byte[0] : in.readAllBytes();
        }
    }

    static Site site(String... policies) throws IOException {
        var site = new Site();
        for (var p : policies) site.register(new Spif(data(p)));
        return site;
    }

    @TestFactory
    Stream<DynamicTest> upstreamVectors() throws IOException {
        var root = Xml.parse(data("tests.xml"));
        var tests = new ArrayList<DynamicTest>();
        for (var sequence : Xml.children(root, "sequence")) {
            var policies = Xml.children(sequence, "policy");
            for (var p : policies)
                tests.add(DynamicTest.dynamicTest("policy " + p.getAttribute("spif"), () -> {
                    if (p.hasAttribute("exception"))
                        assertEquals(p.getAttribute("exception"), assertThrows(SpiffingException.class, () -> new Spif(data(p.getAttribute("spif")))).getMessage());
                    else assertNotNull(new Spif(data(p.getAttribute("spif"))));
                }));
            for (var t : Xml.children(sequence, "test"))
                tests.add(DynamicTest.dynamicTest(t.getAttribute("label") + " " + t.getAttribute("xml:lang") + " " + t.getAttribute("encrypt"), () -> {
                    var site = new Site();
                    for (var p : policies)
                        if (!p.hasAttribute("exception")) site.register(new Spif(data(p.getAttribute("spif"))));
                    if (t.hasAttribute("exception"))
                        assertEquals(t.getAttribute("exception"), assertThrows(SpiffingException.class, () -> check(t, site)).getMessage());
                    else check(t, site);
                }));
        }
        return tests.stream();
    }

    private static void check(Element t, Site site) throws IOException {
        var label = site.label(data(t.getAttribute("label")), Format.ANY);
        String lang = t.getAttribute("xml:lang");
        if (t.hasAttribute("valid"))
            assertEquals(Boolean.parseBoolean(t.getAttribute("valid")), label.policy().valid(label));
        if (t.hasAttribute("label-marking"))
            assertEquals(t.getAttribute("label-marking"), label.policy().displayMarking(label, lang));
        roundTrip(label, site);
        if (t.hasAttribute("encrypt")) {
            label = label.encrypt(t.getAttribute("encrypt"), site);
            roundTrip(label, site);
        }
        if (t.hasAttribute("encrypt-marking"))
            assertEquals(t.getAttribute("encrypt-marking"), label.policy().displayMarking(label, lang));
        if (t.hasAttribute("clearance")) {
            var clearance = site.clearance(data(t.getAttribute("clearance")), Format.ANY);
            if (t.hasAttribute("clearance-marking"))
                assertEquals(t.getAttribute("clearance-marking"), clearance.policy().displayMarking(clearance));
            assertEquals(t.getAttribute("acdf-result").equals("1"), clearance.policy().acdf(label, clearance));
            for (var format : List.of(Format.XML, Format.NATO, Format.DER)) {
                var copy = site.clearance(clearance.write(format), format);
                assertEquals(clearance.classifications(), copy.classifications());
                assertEquals(clearance.categories(), copy.categories());
            }
        }
    }

    static void roundTrip(Label label, Site site) {
        for (var format : List.of(Format.XML, Format.NATO, Format.DER)) {
            var copy = site.label(label.write(format), format);
            assertSame(label.classification(), copy.classification());
            assertEquals(label.categories(), copy.categories());
            assertEquals(label.policy().displayMarking(label), copy.policy().displayMarking(copy));
            assertArrayEquals(label.write(format), copy.write(format));
        }
    }
}
