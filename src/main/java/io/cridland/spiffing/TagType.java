package io.cridland.spiffing;

import org.w3c.dom.Element;

public enum TagType {
    restrictive, enumeratedPermissive, enumeratedRestrictive, permissive, informative;

    public boolean isPermissive() {
        return this == permissive || this == enumeratedPermissive;
    }

    public boolean isRestrictive() {
        return this == restrictive || this == enumeratedRestrictive;
    }

    public TagType normalized() {
        return isPermissive() ? permissive : isRestrictive() ? restrictive : informative;
    }

    static TagType policy(Element e) {
        return switch (Xml.required(e, "tagType")) {
            case "restrictive" -> restrictive;
            case "permissive" -> permissive;
            case "enumerated" -> switch (Xml.required(e, "enumType")) {
                case "permissive" -> enumeratedPermissive;
                case "restrictive" -> enumeratedRestrictive;
                default -> throw new SpiffingException("Unknown enumType");
            };
            case "tagType7", "informative" -> informative;
            default -> throw new SpiffingException("Unknown tagType");
        };
    }

    static TagType parse(String value) {
        try {
            return valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new SpiffingException("Unsupported tag type: " + value, e);
        }
    }
}
