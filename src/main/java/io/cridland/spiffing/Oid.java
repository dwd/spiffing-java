package io.cridland.spiffing;

public final class Oid {
    private Oid() {
    }

    public static final String NATO = "2.16.840.1.101.2.1.8.3";
    public static final String MISSI = "2.16.840.1.101.2.1.8.1";
    public static final String SSL_PRIVILEGE = "2.16.840.1.101.2.1.8.2";
    public static final String RESTRICTIVE = NATO + ".0";
    public static final String ENUMERATED_PERMISSIVE = NATO + ".1";
    public static final String PERMISSIVE = NATO + ".2";
    public static final String INFORMATIVE = NATO + ".3";
    public static final String ENUMERATED_RESTRICTIVE = NATO + ".4";
}
