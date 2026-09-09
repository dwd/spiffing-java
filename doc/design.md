# Spiffing Java design

## Scope and provenance

Spiffing is a Java library for policy-driven security labels and clearances.
It ports the C++ implementation in `../spiffing`, examined at commit
`63c777b66010d706b806a3092fa7864006da6e7a`. Its public package is
`io.cridland.spiffing`; Maven publishes `io.cridland:spiffing:1.0-SNAPSHOT`.
The upstream MIT license is retained and included in the JAR.

The library handles policy interpretation and label processing. XMPP stanza
handling, XEP-0258 enforcement, persistence, and Openfire lifecycle integration
belong to the consumer in `../openfire-spiffing-plugin`. The library has no
Openfire dependency and its tests require no running server or sibling checkout.

## Runtime and dependencies

The user selected Java 17 to match the current Openfire minimum. The original
Maven skeleton targeted Java 22; the port initially preserved that setting.
The current build uses `maven.compiler.release=17`, which constrains both
language features and JDK API usage. Calls to Java 21's `List.getFirst()` were
replaced with `get(0)` where existing checks guarantee a nonempty list.

Bouncy Castle `bcprov-jdk18on:1.84` supplies ASN.1 parsing and DER encoding.
JUnit Jupiter 6.1.0 is test-only. Both dependencies work with the Java 17 build
and test suite. This verifies library compatibility on Java 17, not dependency
resolution or classloader behavior inside a deployed Openfire installation.
The JAR has the automatic module name `io.cridland.spiffing`.

## Model and ownership

`Site` is a registry indexed by policy OID and name. Applications can create
independent registries; `Site.site()` offers an optional process-wide default.
Registration and lookup are synchronized, and duplicate policy IDs or names
are rejected.

`Spif` loads a policy and owns its `Classification`, `TagSet`, `Tag`, and
`Category` definitions. Public APIs do not expose mutators for these definitions.
Internal DOM elements retain policy constraints and equivalence rules. Local
constraint references are checked during policy construction; equivalence
references into a target policy resolve when translation is requested.

`Label` holds one classification and a set of categories. `Clearance` holds an
explicit classification set and category privileges. Both are mutable, expose
unmodifiable collection views, and require external synchronization when shared.
Categories are ordered by their source-policy ordinal for display. Policy
ownership is based on instance identity: matching OIDs do not make independently
loaded policies interchangeable. `Lacv` represents a nonnegative arbitrary
precision integer.

## Validation and access decisions

`Spif.valid` and `assertValid` evaluate excluded classifications, excluded
categories, and required-category groups. A category reference without a LACV
matches any category of that type in its named tagset. Group operations are
`onlyOne`, `oneOrMore`, and `all`; each counts matching group members, and empty
groups do not satisfy a requirement.

`Spif.acdf` is separate from validation, following the C++ API. Callers that
require both must validate the label and then evaluate access. Access requires:

- Explicit clearance membership for the label's classification.
- Every restrictive category in the label.
- At least one matching category for each permissive tag represented in the label.

Informative categories have no access effect and are not clearance privileges.
Classification hierarchy controls clearance display order, not implicit grants.
Permissive groups use tag identity rather than names, so unrelated tags with the
same name cannot satisfy each other's access requirement.

## Markings and equivalence

Display markings follow policy and classification phrases, category/tag phrases,
prefixes, suffixes, separators, location codes, class suppression, and policy
replacement. Language selection tries the exact language, its primary subtag,
and the default. Category display order follows the policy.

`Label.encrypt` retains the upstream name for equivalence translation; it is
not cryptography. It creates a label in the target policy, applies the equivalent
classification, translates or discards categories, and adds equivalence-required
categories. Missing mappings fail without mutating the source label. The caller
chooses whether to validate the translated result. Only the encryption direction
is exposed; there is no decryption API.

## Wire formats and input boundaries

`Wire` dispatches debug XML, NATO XML, and ASN.1. `XML` input accepts known debug
and NATO namespaces; explicit `NATO` input requires the NATO namespace. `ANY`
detects ASN.1 label/clearance roots or delegates to XML parsing, including BOM and
UTF-16 input. Output requires an explicit format.

`Xml` uses namespace-aware JDK DOM parsing and disables DOCTYPE declarations,
external entities, external schemas, and XInclude. `AsnCodec` uses Bouncy Castle
for ESS/X.841 labels, RFC 5912 clearances, ACP-145(A) categories, MISSI PRBAC,
and SSLPrivileges. `BER` and `DER` input accept BER, including indefinite
lengths; both output canonical DER. Unknown category syntaxes, invalid tags,
missing label classifications, trailing ASN.1 data, and policy mismatches fail.

An omitted ASN.1 clearance class list means `{unclassified}` (LACV 1), as RFC
5912 specifies. An explicitly empty class list grants no classifications.
Bitmap positions are limited to 16,777,215 to bound allocation; enumerated
attributes retain arbitrary precision. MISSI cannot disambiguate permissive and
restrictive enumeration in one tagset, so that ambiguous case is rejected.

## Compatibility decisions and limitations

Malformed XML and duplicate/ambiguous definitions are rejected rather than
reproducing permissive parsing or undefined behavior in C++. The copied Food
policies correct the `securityCategiryTagSet` closing-tag typo. The upstream
incomplete `bsi-commercial.xml` remains reference data and is not a valid policy.

Serialization preserves the policy/classification/category model, not original
bytes. ESS privacy marks and NATO timestamps or other metadata outside
confidentiality information are not retained. MISSI local RBAC is unsupported.
Metadata such as `obsolete` and `singleSelection` does not add validation rules
beyond those implemented by the C++ library. The parser is not a complete SPIF
XML Schema validator. There is no live C++ differential harness or Openfire
integration test in this repository.

## Verification

`UpstreamTest` exercises all 31 policy/test scenarios from the copied upstream
`tests.xml`: valid/invalid labels, expected exceptions, localized markings,
equivalence translation, and access decisions. Successful labels and clearances
also round-trip through debug XML, NATO XML, and DER.

`LibraryTest` covers fixed ESS/ACP-145 byte vectors, indefinite BER, RFC 5912
omitted and empty class lists, MISSI/SSLPrivileges, large enumerated LACVs,
permissive/restrictive access boundaries, registry isolation, immutable views,
XML external-entity rejection, namespace and format errors, malformed ASN.1,
constraint operations, marking fallback, and translation source preservation.
An additional regression verifies that equally named permissive tags in separate
tagsets each require a matching clearance privilege.

The Java 17 baseline change was built and tested using OpenJDK 17 with
`JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 mvn -o clean verify`.
Use an appropriate local JDK path on other machines. Run this check again for
baseline or dependency changes; compiling on a newer JDK alone does not establish
runtime compatibility. Record actual commands, results, and limitations in each
commit body rather than treating these instructions as evidence of a test run.
