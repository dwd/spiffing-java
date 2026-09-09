package io.cridland.spiffing;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Registry of policies. Use separate instances to isolate independent applications.
 */
public final class Site {
    private static final Site DEFAULT = new Site();
    private final Map<String, Spif> ids = new HashMap<>(), names = new HashMap<>();

    public static Site site() {
        return DEFAULT;
    }

    public synchronized Spif spif(String id) {
        var p = ids.get(id);
        if (p == null) throw new SpiffingException("Unknown policy id: " + id);
        return p;
    }

    public synchronized Spif spifByName(String name) {
        var p = names.get(name);
        if (p == null) throw new SpiffingException("Unknown policy name: " + name);
        return p;
    }

    public synchronized Spif register(Spif policy) {
        if (ids.containsKey(policy.policyId()) || names.containsKey(policy.name()))
            throw new SpiffingException("Duplicate policy: " + policy.policyId());
        ids.put(policy.policyId(), policy);
        names.put(policy.name(), policy);
        return policy;
    }

    public Spif load(String xml) {
        return register(new Spif(xml));
    }

    public Spif load(InputStream in) throws IOException {
        return register(new Spif(in));
    }

    public Spif load(Path path) throws IOException {
        try (var in = Files.newInputStream(path)) {
            return load(in);
        }
    }

    public Label label(byte[] data, Format format) {
        return Label.parse(data, format, this);
    }

    public Label label(String xml) {
        return label(xml.getBytes(StandardCharsets.UTF_8), Format.XML);
    }

    public Clearance clearance(byte[] data, Format format) {
        return Clearance.parse(data, format, this);
    }

    public Clearance clearance(String xml) {
        return clearance(xml.getBytes(StandardCharsets.UTF_8), Format.XML);
    }
}
