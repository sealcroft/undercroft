//! **Every row tag's canonical, in ONE module** (ROADMAP O406 item 1).
//!
//! Nine tables carry a tag recomputed in place: drawers, drawer supersession
//! receipts, facts, fact receipts, entities, tunnels, wing trust, retention
//! policies and the pushed-embedder marker. Each has ONE builder here, every
//! call site goes through it — `rotate.rs` and the tag walk included — and
//! each takes the [`RowFormat`] it builds in as a REQUIRED argument, so no
//! call site can tag in a format it did not state. The version-1 recipes are
//! private to this module, and [`undercroft_vault::Vault::row_tag`] takes a
//! [`RowCanonical`]; in this crate only these functions make one, which
//! `only_this_module_makes_a_row_canonical` counts against the production
//! source (`RowEncoder::new(` and `RowCanonical::v1(`, both `pub` in the
//! vault crate). `Vault::tag` takes bare bytes and stays the record-only
//! canonicals' door; nothing but review keeps a row off it.
//!
//! **Version 1** is byte for byte what every tag before O406 covered: fields
//! joined by 0x1f (0x1b–0x1e before the fact and entity extensions), no
//! lengths, no table domain for five of the nine, NULL written as `''`. A
//! verified version-1 tag proves the CONCATENATION and never where each
//! field ends — measured, a fact's tag moved onto a drawer row with no key
//! verified, and the drawer was served (`transplant_tests`).
//!
//! **Version 2** ([`undercroft_vault::RowEncoder`]) is unambiguous by
//! construction: `undercroft.row.v2/<table>` first, every required field
//! length-prefixed, every optional field a numbered TLV where absent is not
//! empty, under the `row` subkey. Every value is encoded **as the database
//! returns it**: `confidence` is canonicalised so a `-0.0` written is the
//! `+0.0` read back, and a retention period is the integer the column holds.

use undercroft_vault::{RowCanonical, RowEncoder, RowFormat, Vault};

/// Every field a fact's tag covers, so the builder's argument is the fact
/// rather than an assortment. Optional fields are `None` when the column is
/// NULL — never `Some("")`, which version 2 tells apart from it.
#[derive(Clone, Copy)]
pub(crate) struct FactFields<'a> {
    pub id: &'a [u8],
    pub subject: &'a [u8],
    pub predicate: &'a [u8],
    pub object: &'a [u8],
    pub valid_from: Option<&'a [u8]>,
    pub valid_to: Option<&'a [u8]>,
    pub confidence: f64,
    pub support: Option<&'a [u8]>,
    pub authority_class: Option<&'a [u8]>,
    pub review_state: Option<&'a [u8]>,
    pub canonical_key: Option<&'a [u8]>,
    pub extractor: Option<&'a [u8]>,
    pub terms: Option<&'a [u8]>,
}

/// A fact's confidence as the database returns it: SQLite reads a stored
/// `-0.0` back as `+0.0`, so the sign of zero is not part of the value.
fn stored_confidence(c: f64) -> [u8; 8] {
    let c = if c == 0.0 { 0.0 } else { c };
    c.to_le_bytes()
}

/// A drawer: `id`, the covered `meta_json` and the at-rest content.
pub(crate) fn drawer(
    f: RowFormat,
    id: impl AsRef<[u8]>,
    meta_json: &[u8],
    content: &[u8],
) -> RowCanonical {
    let id = id.as_ref();
    match f {
        RowFormat::V1 => RowCanonical::v1(v1::drawer(id, meta_json, content)),
        RowFormat::V2 => RowEncoder::new("drawer")
            .field(id)
            .field(meta_json)
            .field(content)
            .finish(),
    }
}

/// A drawer's tag checked over its at-rest bytes in `f` — the one check every
/// drawer read makes, so the drawer verify sites stay countable by one name.
pub(crate) fn verify_drawer(
    vault: &Vault,
    f: RowFormat,
    id: impl AsRef<[u8]>,
    meta_json: &[u8],
    content: &[u8],
    tag: &[u8],
) -> Result<(), undercroft_vault::VaultError> {
    vault.verify_row_tag(&drawer(f, id, meta_json, content), tag)
}

/// A drawer supersession receipt: the superseding drawer, the superseded
/// one, and the keyed fingerprint of the superseded content.
pub(crate) fn supersession(
    f: RowFormat,
    drawer_id: &str,
    supersedes: &str,
    source_fp: &[u8],
) -> RowCanonical {
    match f {
        RowFormat::V1 => RowCanonical::v1(v1::receipt(
            drawer_id.as_bytes(),
            supersedes.as_bytes(),
            source_fp,
        )),
        RowFormat::V2 => RowEncoder::new("drawer-supersession")
            .field(drawer_id.as_bytes())
            .field(supersedes.as_bytes())
            .field(source_fp)
            .finish(),
    }
}

/// A fact.
pub(crate) fn fact(f: RowFormat, x: &FactFields<'_>) -> RowCanonical {
    match f {
        RowFormat::V1 => RowCanonical::v1(v1::fact(x)),
        RowFormat::V2 => RowEncoder::new("fact")
            .field(x.id)
            .field(x.subject)
            .field(x.predicate)
            .field(x.object)
            .field(&stored_confidence(x.confidence))
            .optional(1, x.valid_from)
            .optional(2, x.valid_to)
            .optional(3, x.support)
            .optional(4, x.authority_class)
            .optional(5, x.review_state)
            .optional(6, x.canonical_key)
            .optional(7, x.extractor)
            .optional(8, x.terms)
            .finish(),
    }
}

/// A fact's receipt: the fact, the drawer it cites, and the keyed
/// fingerprint of that drawer's content.
pub(crate) fn fact_receipt(
    f: RowFormat,
    triple_id: &str,
    source_drawer_id: &str,
    source_fp: &[u8],
) -> RowCanonical {
    match f {
        RowFormat::V1 => RowCanonical::v1(v1::receipt(
            triple_id.as_bytes(),
            source_drawer_id.as_bytes(),
            source_fp,
        )),
        RowFormat::V2 => RowEncoder::new("fact-receipt")
            .field(triple_id.as_bytes())
            .field(source_drawer_id.as_bytes())
            .field(source_fp)
            .finish(),
    }
}

/// A graph entity: id, the name at rest (a blind index on a sealed vault),
/// its type, its creation time, and the sealed name where there is one.
pub(crate) fn entity(
    f: RowFormat,
    id: impl AsRef<[u8]>,
    name: impl AsRef<[u8]>,
    etype: impl AsRef<[u8]>,
    created_at: impl AsRef<[u8]>,
    name_rest: Option<&[u8]>,
) -> RowCanonical {
    let (id, name, etype, created_at) = (
        id.as_ref(),
        name.as_ref(),
        etype.as_ref(),
        created_at.as_ref(),
    );
    match f {
        RowFormat::V1 => RowCanonical::v1(v1::entity(id, name, etype, created_at, name_rest)),
        RowFormat::V2 => RowEncoder::new("entity")
            .field(id)
            .field(name)
            .field(etype)
            .field(created_at)
            .optional(1, name_rest)
            .finish(),
    }
}

/// A tunnel between two wings.
pub(crate) fn tunnel(
    f: RowFormat,
    id: impl AsRef<[u8]>,
    from: impl AsRef<[u8]>,
    to: impl AsRef<[u8]>,
    label: impl AsRef<[u8]>,
    created: impl AsRef<[u8]>,
) -> RowCanonical {
    let fields = [
        id.as_ref(),
        from.as_ref(),
        to.as_ref(),
        label.as_ref(),
        created.as_ref(),
    ];
    match f {
        RowFormat::V1 => RowCanonical::v1(crate::manage::joined(b"tunnel", &fields)),
        RowFormat::V2 => fields
            .iter()
            .fold(RowEncoder::new("tunnel"), |e, v| e.field(v))
            .finish(),
    }
}

/// A wing's declared trust class.
pub(crate) fn wing_trust(
    f: RowFormat,
    wing: impl AsRef<[u8]>,
    trust: impl AsRef<[u8]>,
    assigned_at: impl AsRef<[u8]>,
) -> RowCanonical {
    let fields = [wing.as_ref(), trust.as_ref(), assigned_at.as_ref()];
    match f {
        RowFormat::V1 => RowCanonical::v1(crate::manage::joined(b"wingtrust", &fields)),
        RowFormat::V2 => fields
            .iter()
            .fold(RowEncoder::new("wing-trust"), |e, v| e.field(v))
            .finish(),
    }
}

/// A declared retention policy. The period is the INTEGER the column holds,
/// eight bytes little-endian in version 2; version 1 wrote it in decimal.
pub(crate) fn retention(
    f: RowFormat,
    wing: impl AsRef<[u8]>,
    room: impl AsRef<[u8]>,
    days: u32,
    at: impl AsRef<[u8]>,
) -> RowCanonical {
    match f {
        RowFormat::V1 => RowCanonical::v1(crate::manage::joined(
            b"retention",
            &[
                wing.as_ref(),
                room.as_ref(),
                days.to_string().as_bytes(),
                at.as_ref(),
            ],
        )),
        RowFormat::V2 => RowEncoder::new("retention")
            .field(wing.as_ref())
            .field(room.as_ref())
            .field(&i64::from(days).to_le_bytes())
            .field(at.as_ref())
            .finish(),
    }
}

/// The remote mirror's record of which embedding space it was pushed in.
pub(crate) fn pushed_embedder(f: RowFormat, name: &str) -> RowCanonical {
    match f {
        RowFormat::V1 => RowCanonical::v1(format!("indexpushed\x1f{name}").into_bytes()),
        RowFormat::V2 => RowEncoder::new("index-pushed")
            .field(name.as_bytes())
            .finish(),
    }
}

/// The version-1 recipes, private: reachable only through the builders
/// above, which take the format.
mod v1 {
    use super::FactFields;

    pub(super) fn drawer(id: &[u8], meta_json: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(id.len() + meta_json.len() + content.len() + 2);
        out.extend_from_slice(id);
        out.push(0x1f);
        out.extend_from_slice(meta_json);
        out.push(0x1f);
        out.extend_from_slice(content);
        out
    }

    /// Both receipt kinds: the same three fields, the same join — which is
    /// how a fact receipt and a supersession receipt over one triple of
    /// bytes shared a tag (version 2 gives each its domain).
    pub(super) fn receipt(a: &[u8], b: &[u8], fp: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(a);
        out.push(0x1f);
        out.extend_from_slice(b);
        out.push(0x1f);
        out.extend_from_slice(fp);
        out
    }

    /// `id 1f subject 1f predicate 1f from 1f to 1f confidence(8) 1f object`
    /// then the extensions, each with its separator INSIDE its branch: support
    /// (0x1f), authority (0x1e then three 0x1f-led values), extractor
    /// (0x1d 0x1f), terms (0x1c). An absent date and an empty one are one
    /// byte string here.
    pub(super) fn fact(x: &FactFields<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [
            x.id,
            x.subject,
            x.predicate,
            x.valid_from.unwrap_or(b""),
            x.valid_to.unwrap_or(b""),
        ] {
            out.extend_from_slice(part);
            out.push(0x1f);
        }
        out.extend_from_slice(&x.confidence.to_le_bytes());
        out.push(0x1f);
        out.extend_from_slice(x.object);
        if let Some(sup) = x.support {
            out.push(0x1f);
            out.extend_from_slice(sup);
        }
        if x.authority_class.is_some() || x.review_state.is_some() || x.canonical_key.is_some() {
            out.push(0x1e);
            for part in [
                x.authority_class.unwrap_or(b""),
                x.review_state.unwrap_or(b""),
                x.canonical_key.unwrap_or(b""),
            ] {
                out.push(0x1f);
                out.extend_from_slice(part);
            }
        }
        if let Some(e) = x.extractor {
            out.push(0x1d);
            out.push(0x1f);
            out.extend_from_slice(e);
        }
        if let Some(t) = x.terms {
            out.push(0x1c);
            out.extend_from_slice(t);
        }
        out
    }

    pub(super) fn entity(
        id: &[u8],
        name: &[u8],
        etype: &[u8],
        created_at: &[u8],
        name_rest: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, part) in [id, name, etype, created_at].into_iter().enumerate() {
            if i > 0 {
                out.push(0x1f);
            }
            out.extend_from_slice(part);
        }
        if let Some(blob) = name_rest {
            out.push(0x1b);
            out.extend_from_slice(blob);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    /// **The one-module claim, counted** (review of O406): no production
    /// file of this crate but this one builds a row canonical by hand. The
    /// needles are the two `pub` constructors the vault crate exports; the
    /// premise is that this module itself holds both.
    #[test]
    fn only_this_module_makes_a_row_canonical() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let needles = [
            concat!("RowEncoder", "::new("),
            concat!("RowCanonical", "::v1("),
        ];
        let me = std::fs::read_to_string(src.join("rows.rs")).unwrap();
        for n in needles {
            assert!(me.contains(n), "premise: this module makes one with {n}");
        }
        let mut sites = Vec::new();
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".rs") || name == "rows.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let prod = text
                .split(concat!("#[cfg(test)]\n", "mod tests"))
                .next()
                .unwrap();
            for n in needles {
                if prod.contains(n) {
                    sites.push(format!("{name}: {n}"));
                }
            }
        }
        assert!(
            sites.is_empty(),
            "a row canonical built outside rows.rs: {sites:?}"
        );
    }

    use super::*;

    fn fact_with(
        id: &[u8],
        object: &[u8],
        vf: Option<&[u8]>,
        sup: Option<&[u8]>,
    ) -> FactFields<'static> {
        let leak = |b: &[u8]| -> &'static [u8] { Box::leak(b.to_vec().into_boxed_slice()) };
        FactFields {
            id: leak(id),
            subject: b"s",
            predicate: b"p",
            object: leak(object),
            valid_from: vf.map(leak),
            valid_to: None,
            confidence: 0.5,
            support: sup.map(leak),
            authority_class: None,
            review_state: None,
            canonical_key: None,
            extractor: None,
            terms: None,
        }
    }

    /// **ROADMAP O406 P15g, the per-table half**: each measured version-1
    /// ambiguity, rebuilt here as two different rows with ONE version-1
    /// canonical, has two version-2 canonicals.
    #[test]
    fn every_measured_v1_collision_is_two_v2_canonicals() {
        // A drawer's meta/content boundary moved to a separator in content.
        let (a, b) = (
            drawer(RowFormat::V1, "i", b"{}", b"x\x1fy"),
            drawer(RowFormat::V1, "i", b"{}\x1fx", b"y"),
        );
        assert_eq!(a.bytes(), b.bytes(), "premise: one version-1 canonical");
        assert_ne!(
            drawer(RowFormat::V2, "i", b"{}", b"x\x1fy"),
            drawer(RowFormat::V2, "i", b"{}\x1fx", b"y")
        );
        // A fact's NULL date against an empty one.
        let open = fact_with(b"f", b"o", None, None);
        let empty = FactFields {
            valid_from: Some(b""),
            ..open
        };
        assert_eq!(fact(RowFormat::V1, &open), fact(RowFormat::V1, &empty));
        assert_ne!(fact(RowFormat::V2, &open), fact(RowFormat::V2, &empty));
        // A fact's support glued onto its object.
        let grounded = fact_with(b"f", b"o", None, Some(b"{support}"));
        let glued = fact_with(b"f", b"o\x1f{support}", None, None);
        assert_eq!(fact(RowFormat::V1, &grounded), fact(RowFormat::V1, &glued));
        assert_ne!(fact(RowFormat::V2, &grounded), fact(RowFormat::V2, &glued));
        // A fact's tag transplanted onto a drawer row (P15i), and an
        // entity's.
        let f = fact_with(b"0123", b"o", None, None);
        let fact_bytes = fact(RowFormat::V1, &f).bytes().to_vec();
        let mut tail = b"p\x1f\x1f\x1f".to_vec();
        tail.extend_from_slice(&0.5f64.to_le_bytes());
        tail.extend_from_slice(b"\x1fo");
        assert_eq!(
            drawer(RowFormat::V1, "0123", b"s", &tail).bytes(),
            &fact_bytes[..],
            "premise: a drawer and a fact share one version-1 canonical"
        );
        assert_ne!(
            drawer(RowFormat::V2, "0123", b"s", &tail).bytes(),
            fact(RowFormat::V2, &f).bytes()
        );
        assert_eq!(
            drawer(RowFormat::V1, "e", b"n", b"unknown\x1ft").bytes(),
            entity(RowFormat::V1, "e", "n", "unknown", "t", None).bytes()
        );
        assert_ne!(
            drawer(RowFormat::V2, "e", b"n", b"unknown\x1ft").bytes(),
            entity(RowFormat::V2, "e", "n", "unknown", "t", None).bytes()
        );
        // The two receipt kinds over one triple of bytes.
        assert_eq!(
            supersession(RowFormat::V1, "a", "b", b"fp"),
            fact_receipt(RowFormat::V1, "a", "b", b"fp")
        );
        assert_ne!(
            supersession(RowFormat::V2, "a", "b", b"fp"),
            fact_receipt(RowFormat::V2, "a", "b", b"fp")
        );
        // A tunnel label truncated into its creation time.
        assert_eq!(
            tunnel(RowFormat::V1, "i", "a", "b", "l\x1fx", "t"),
            tunnel(RowFormat::V1, "i", "a", "b", "l", "x\x1ft")
        );
        assert_ne!(
            tunnel(RowFormat::V2, "i", "a", "b", "l\x1fx", "t"),
            tunnel(RowFormat::V2, "i", "a", "b", "l", "x\x1ft")
        );
    }

    /// Version 2 encodes what the database RETURNS: a `-0.0` confidence
    /// written is a `+0.0` read back, and the two canonicals are one.
    #[test]
    fn a_negative_zero_confidence_has_the_canonical_it_reads_back_with() {
        let pos = fact_with(b"f", b"o", None, None);
        let neg = FactFields {
            confidence: -0.0,
            ..pos
        };
        let zero = FactFields {
            confidence: 0.0,
            ..pos
        };
        assert_eq!(fact(RowFormat::V2, &neg), fact(RowFormat::V2, &zero));
        assert_ne!(
            fact(RowFormat::V1, &neg),
            fact(RowFormat::V1, &zero),
            "premise: version 1 tags the sign it was handed (ROADMAP O419)"
        );
    }

    /// The version-1 recipes are byte for byte what the tree tagged before
    /// O406 — pinned against hand-written literals, because every row
    /// written before the walk is verified under them.
    #[test]
    fn the_v1_recipes_are_the_released_bytes() {
        assert_eq!(
            drawer(RowFormat::V1, "i", b"m", b"c").bytes(),
            b"i\x1fm\x1fc"
        );
        assert_eq!(
            fact_receipt(RowFormat::V1, "t", "d", b"fp").bytes(),
            b"t\x1fd\x1ffp"
        );
        assert_eq!(
            entity(RowFormat::V1, "i", "n", "e", "c", Some(b"r")).bytes(),
            b"i\x1fn\x1fe\x1fc\x1br"
        );
        assert_eq!(
            wing_trust(RowFormat::V1, "w", "t", "a").bytes(),
            b"wingtrust\x1fw\x1ft\x1fa"
        );
        assert_eq!(
            retention(RowFormat::V1, "w", "r", 30, "a").bytes(),
            b"retention\x1fw\x1fr\x1f30\x1fa"
        );
        assert_eq!(
            tunnel(RowFormat::V1, "i", "f", "t", "l", "c").bytes(),
            b"tunnel\x1fi\x1ff\x1ft\x1fl\x1fc"
        );
        assert_eq!(
            pushed_embedder(RowFormat::V1, "h").bytes(),
            b"indexpushed\x1fh"
        );
        let mut want = b"i\x1fs\x1fp\x1ff\x1f\x1f".to_vec();
        want.extend_from_slice(&0.5f64.to_le_bytes());
        want.extend_from_slice(b"\x1fo\x1fS\x1e\x1fcanonical\x1fapproved\x1fk\x1d\x1fx\x1cT");
        let full = FactFields {
            id: b"i",
            subject: b"s",
            predicate: b"p",
            object: b"o",
            valid_from: Some(b"f"),
            valid_to: None,
            confidence: 0.5,
            support: Some(b"S"),
            authority_class: Some(b"canonical"),
            review_state: Some(b"approved"),
            canonical_key: Some(b"k"),
            extractor: Some(b"x"),
            terms: Some(b"T"),
        };
        assert_eq!(fact(RowFormat::V1, &full).bytes(), &want[..]);
    }
}
