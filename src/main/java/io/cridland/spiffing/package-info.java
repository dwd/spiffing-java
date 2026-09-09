/**
 * Policy-driven security labels and clearances, ported from the MIT-licensed
 * C++ Spiffing library by Dave Cridland and Surevine Ltd.
 *
 * <p>Load policies into a {@link io.cridland.spiffing.Site}, then parse or create
 * labels and clearances. {@link io.cridland.spiffing.Spif#valid} checks label
 * constraints; {@link io.cridland.spiffing.Spif#acdf} makes the separate access
 * decision. Classification hierarchy is used for display ordering, not as an
 * implicit grant of lower classifications.
 *
 * <p>Policies are immutable after construction. Registries synchronize policy
 * registration and lookup. Labels and clearances are mutable and require external
 * synchronization if shared between threads.
 */
package io.cridland.spiffing;
