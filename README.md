# Spiffing for Java

A Java port of the C++ [Spiffing](https://github.com/surevine/spiffing) library for policy-driven security labels and clearances.

It loads Open XML SPIF policies, generates display markings, validates labels, makes access decisions, and translates labels between equivalent policies.

Requires Java 22 or later and Maven 3.9 or later. Bouncy Castle supplies the ASN.1 implementation; no native libraries are needed.

```sh
mvn verify
```

The library JAR is written to `target/spiffing-1.0-SNAPSHOT.jar`. Use `mvn install` to install it in your local Maven repository, then add:

```xml
<dependency>
    <groupId>io.cridland</groupId>
    <artifactId>spiffing</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

## Usage

```java
import io.cridland.spiffing.*;
import java.nio.file.Files;
import java.nio.file.Path;

Site site = new Site();
Spif policy = site.load(Path.of("policy.xml"));
Label label = site.label(Files.readAllBytes(Path.of("label.xml")), Format.ANY);
Clearance clearance = site.clearance(
        Files.readAllBytes(Path.of("clearance.ber")), Format.BER);

policy.assertValid(label);
boolean allowed = policy.acdf(label, clearance);
String marking = policy.displayMarking(label, "en-GB", MarkingCode.pageBottom);
byte[] der = label.write(Format.DER);
byte[] nato = label.write(Format.NATO);
```

For the bundled Food policy, a label can also be built programmatically:

```java
Site site = new Site();
Spif food = site.load(Path.of("src/test/resources/test-data/food-policy.xml"));
Label water = new Label(food, 50);
water.addCategory(food.tagSetLookupByName("Ethics")
        .categoryLookup(TagType.permissive, 1));
System.out.println(food.displayMarking(water)); // [ Food FREE British Flag ]
```

Load both policies into the same registry before translating:

```java
Label translated = label.encrypt(targetPolicy.policyId(), site);
```

`encrypt` retains the C++ API's terminology: it applies equivalence mappings and required-category additions. It does **not** perform cryptography. Missing mappings raise `SpiffingException`; the source label remains unchanged. As in C++, callers decide whether to validate the resulting label.

Use a separate `Site` per application or tenant. `Site.site()` provides an optional process-wide registry for the static parsing overloads. A registry rejects duplicate policy IDs or names. Categories, labels and clearances belong to a specific policy instance; mixing instances is rejected, even if their OIDs match.

## Formats and behavior

| Format | Labels | Clearances |
|---|---|---|
| `XML` | Spiffy debug XML | Spiffy debug XML |
| `NATO` | ADaTP-4774 originator confidentiality label | NATO confidentiality clearance |
| `BER` / `DER` | ESS/X.841 security label | RFC 5912 clearance |
| `ANY` | Detect XML or ASN.1 input | Detect XML or ASN.1 input |

`XML` input also recognizes NATO namespaces. `NATO` input requires the NATO namespace. Both `BER` and `DER` accept BER encodings, including indefinite lengths, and write canonical DER. ASN.1 categories support ACP-145(A), MISSI PRBAC labels, and SSLPrivileges clearances. Informative label categories support both bitmap and enumerated values. LACVs use arbitrary precision integers; bitmap positions are limited to 16,777,215 to bound allocation.

Access decisions require explicit classification membership, every restrictive category, and at least one matching category for each permissive tag represented in the label. Informative categories do not affect access. Classification hierarchy orders clearance markings; it does not imply access to lower classifications. `acdf` and `valid` are separate operations, matching the C++ API.

Validation supports excluded classifications/categories and `onlyOne`, `oneOrMore`, and `all` required-category groups. Markings support policy/class/category phrases, tag qualifiers, location codes, policy replacement, class suppression, and exact language → primary language → default fallback.

## Compatibility and limits

Ported from sibling project `../spiffing` at commit `63c777b66010d706b806a3092fa7864006da6e7a`. All 31 policy/test scenarios from its `test-data/tests.xml` are exercised, with additional format round trips and focused regression tests. Tests are self-contained; the C++ checkout is not required to build.

The Java port deliberately rejects malformed XML, external entities, duplicate/ambiguous definitions, unknown ASN.1 category syntaxes, missing label classifications, and cross-instance policy mixing. It honors the RFC 5912 default `{unclassified}` when the ASN.1 clearance class list is omitted; an explicitly empty list remains empty. These choices avoid permissive parsing and undefined behavior in the C++ implementation. Permissive access groups use tag identity, preventing unrelated tags with identical names from sharing an access check.

As in the original, ESS privacy marks are not retained, MISSI local RBAC is unsupported, and equivalence translation exposes the encryption direction only. SPIF metadata such as `obsolete` and `singleSelection` does not add validation rules beyond the C++ implementation. NATO timestamps and other metadata outside confidentiality information are not retained. Serialization preserves the policy/classification/category model, not the original document bytes.

The copied `food-policy.xml` and `food-policy-missi.xml` fixtures correct the original `securityCategiryTagSet` closing-tag typo. The incomplete upstream `bsi-commercial.xml` is retained as reference data and is not a valid policy. See [LICENSE](LICENSE) for the original MIT copyright and permission notice.
