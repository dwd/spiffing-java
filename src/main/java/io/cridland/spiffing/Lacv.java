package io.cridland.spiffing;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Nonnegative, arbitrary precision label attribute code value.
 */
public record Lacv(BigInteger value) implements Comparable<Lacv> {
    public Lacv {
        Objects.requireNonNull(value);
        if (value.signum() < 0) throw new SpiffingException("Negative LACV");
    }

    public Lacv(long value) {
        this(BigInteger.valueOf(value));
    }

    public static Lacv parse(String value) {
        try {
            return new Lacv(new BigInteger(value));
        } catch (NumberFormatException e) {
            throw new SpiffingException("Invalid LACV: " + value, e);
        }
    }

    @Override
    public int compareTo(Lacv other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
