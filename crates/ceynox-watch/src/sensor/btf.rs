//! A minimal reader for the kernel's BTF type information, enough to answer
//! one question: at which byte offset does field `f` sit in `struct s` on
//! the running kernel?
//!
//! The kernel programs read a handful of kernel struct fields. Their layout
//! differs between kernel versions and build configurations, so the loader
//! looks the offsets up here (from `/sys/kernel/btf/vmlinux`) instead of
//! compiling them in.
//!
//! The parser treats its input as untrusted: every read is bounds-checked
//! and recursion is depth-limited, so a malformed blob yields an error, never
//! a panic or an out-of-bounds read.

use std::fmt;

const MAGIC: u16 = 0xEB9F;
const HEADER_LEN: usize = 24;
/// Size of the fixed part of every type record.
const TYPE_LEN: usize = 12;
/// Size of one struct/union member record.
const MEMBER_LEN: usize = 12;

const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;
const KIND_MAX: u32 = 19;

/// Anonymous members nest only a few levels deep in practice.
const MAX_DEPTH: u32 = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum BtfError {
    /// Not BTF, or BTF for the other byte order.
    BadMagic,
    /// A length or offset points outside the data.
    Truncated,
    /// A type kind this reader does not know how to skip.
    UnknownKind(u32),
    NoSuchStruct(String),
    NoSuchField {
        strukt: String,
        field: String,
    },
    /// The field is a bitfield or not byte-aligned.
    NotByteAligned {
        strukt: String,
        field: String,
    },
}

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not native-endian BTF data"),
            Self::Truncated => write!(f, "BTF data is truncated or corrupt"),
            Self::UnknownKind(k) => write!(f, "BTF type kind {k} is not supported"),
            Self::NoSuchStruct(s) => write!(f, "kernel has no `struct {s}`"),
            Self::NoSuchField { strukt, field } => {
                write!(f, "kernel `struct {strukt}` has no field `{field}`")
            }
            Self::NotByteAligned { strukt, field } => {
                write!(f, "`{strukt}.{field}` is a bitfield")
            }
        }
    }
}

impl std::error::Error for BtfError {}

/// Parsed BTF: the raw bytes plus where each type id starts.
#[derive(Debug)]
pub struct Btf<'a> {
    types: &'a [u8],
    strings: &'a [u8],
    /// Byte offset into `types` of type id `i + 1` (id 0 is `void`).
    index: Vec<u32>,
    /// Ids of the structs that have members, the only ones ever looked up.
    structs: Vec<u32>,
}

#[derive(Clone, Copy)]
struct TypeRec {
    name_off: u32,
    kind: u32,
    vlen: u32,
    kflag: bool,
    /// `size` for sized kinds, the referenced type id for the rest.
    size_or_type: u32,
    /// Offset in `types` of the kind-specific data after the fixed part.
    extra: usize,
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, BtfError> {
    let s = b.get(off..off.checked_add(2).ok_or(BtfError::Truncated)?).ok_or(BtfError::Truncated)?;
    Ok(u16::from_ne_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, BtfError> {
    let s = b.get(off..off.checked_add(4).ok_or(BtfError::Truncated)?).ok_or(BtfError::Truncated)?;
    Ok(u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

impl<'a> Btf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, BtfError> {
        if u16_at(data, 0)? != MAGIC {
            return Err(BtfError::BadMagic);
        }
        let hdr_len = u32_at(data, 4)? as usize;
        if hdr_len < HEADER_LEN {
            return Err(BtfError::Truncated);
        }
        let section = |off_at: usize, len_at: usize| -> Result<&'a [u8], BtfError> {
            let start = hdr_len.checked_add(u32_at(data, off_at)? as usize).ok_or(BtfError::Truncated)?;
            let end = start.checked_add(u32_at(data, len_at)? as usize).ok_or(BtfError::Truncated)?;
            data.get(start..end).ok_or(BtfError::Truncated)
        };
        let types = section(8, 12)?;
        let strings = section(16, 20)?;

        let mut index = Vec::new();
        let mut structs = Vec::new();
        let mut at = 0usize;
        while at < types.len() {
            index.push(u32::try_from(at).map_err(|_| BtfError::Truncated)?);
            let info = u32_at(types, at + 4)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            // An empty struct is how a forward declaration's stand-in looks.
            if kind == KIND_STRUCT && vlen != 0 {
                structs.push(index.len() as u32);
            }
            let extra = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => vlen * 12,
                KIND_ENUM | KIND_FUNC_PROTO => vlen * 8,
                k if k <= KIND_MAX => 0,
                k => return Err(BtfError::UnknownKind(k)),
            };
            at = at.checked_add(TYPE_LEN + extra).ok_or(BtfError::Truncated)?;
        }
        if at != types.len() {
            return Err(BtfError::Truncated);
        }
        Ok(Self { types, strings, index, structs })
    }

    fn rec(&self, id: u32) -> Result<TypeRec, BtfError> {
        let slot = (id as usize).checked_sub(1).ok_or(BtfError::Truncated)?;
        let at = *self.index.get(slot).ok_or(BtfError::Truncated)? as usize;
        let info = u32_at(self.types, at + 4)?;
        Ok(TypeRec {
            name_off: u32_at(self.types, at)?,
            kind: (info >> 24) & 0x1f,
            vlen: info & 0xffff,
            kflag: info >> 31 != 0,
            size_or_type: u32_at(self.types, at + 8)?,
            extra: at + TYPE_LEN,
        })
    }

    fn name(&self, off: u32) -> Result<&'a [u8], BtfError> {
        let rest = self.strings.get(off as usize..).ok_or(BtfError::Truncated)?;
        let end = rest.iter().position(|&b| b == 0).ok_or(BtfError::Truncated)?;
        Ok(&rest[..end])
    }

    /// Strip typedefs and qualifiers to reach the underlying type.
    fn resolve(&self, mut id: u32) -> Result<Option<TypeRec>, BtfError> {
        for _ in 0..MAX_DEPTH {
            if id == 0 {
                return Ok(None); // void
            }
            let rec = self.rec(id)?;
            match rec.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                    id = rec.size_or_type;
                }
                _ => return Ok(Some(rec)),
            }
        }
        Err(BtfError::Truncated)
    }

    /// Byte offset of `field` in `struct strukt`, looking through anonymous
    /// structs and unions nested inside it.
    pub fn field_offset(&self, strukt: &str, field: &str) -> Result<u32, BtfError> {
        let mut found_struct = false;
        for &id in &self.structs {
            let rec = self.rec(id)?;
            if self.name(rec.name_off)? != strukt.as_bytes() {
                continue;
            }
            found_struct = true;
            if let Some(bits) = self.find_member(&rec, field.as_bytes(), 0)? {
                let bits =
                    bits.ok_or_else(|| BtfError::NotByteAligned { strukt: strukt.into(), field: field.into() })?;
                return Ok(bits / 8);
            }
        }
        if found_struct {
            Err(BtfError::NoSuchField { strukt: strukt.into(), field: field.into() })
        } else {
            Err(BtfError::NoSuchStruct(strukt.into()))
        }
    }

    /// Size in bytes of `struct strukt`.
    pub fn struct_size(&self, strukt: &str) -> Result<u32, BtfError> {
        for &id in &self.structs {
            let rec = self.rec(id)?;
            if self.name(rec.name_off)? == strukt.as_bytes() {
                return Ok(rec.size_or_type);
            }
        }
        Err(BtfError::NoSuchStruct(strukt.into()))
    }

    /// `Some(Some(bit_offset))` when found and byte-aligned, `Some(None)` when
    /// found but a bitfield, `None` when absent.
    fn find_member(&self, rec: &TypeRec, field: &[u8], depth: u32) -> Result<Option<Option<u32>>, BtfError> {
        if depth > MAX_DEPTH {
            return Err(BtfError::Truncated);
        }
        for i in 0..rec.vlen as usize {
            let at = rec.extra + i * MEMBER_LEN;
            let name_off = u32_at(self.types, at)?;
            let type_id = u32_at(self.types, at + 4)?;
            let raw = u32_at(self.types, at + 8)?;
            // With kflag set the top byte is a bitfield width.
            let (bit_off, bitfield) = if rec.kflag { (raw & 0x00ff_ffff, raw >> 24 != 0) } else { (raw, false) };

            if name_off != 0 {
                if self.name(name_off)? == field {
                    return Ok(Some((!bitfield && bit_off % 8 == 0).then_some(bit_off)));
                }
                continue;
            }
            // Anonymous member: its fields belong to the enclosing struct.
            let Some(inner) = self.resolve(type_id)? else { continue };
            if inner.kind != KIND_STRUCT && inner.kind != KIND_UNION {
                continue;
            }
            match self.find_member(&inner, field, depth + 1)? {
                Some(Some(inner_bits)) => {
                    let total = bit_off.checked_add(inner_bits).ok_or(BtfError::Truncated)?;
                    return Ok(Some(Some(total)));
                }
                Some(None) => return Ok(Some(None)),
                None => {}
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a BTF blob type by type.
    #[derive(Default)]
    struct Builder {
        types: Vec<u8>,
        strings: Vec<u8>,
        next_id: u32,
    }

    impl Builder {
        fn new() -> Self {
            Self { types: vec![], strings: vec![0], next_id: 1 }
        }
        fn s(&mut self, name: &str) -> u32 {
            if name.is_empty() {
                return 0;
            }
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            off
        }
        fn head(&mut self, name: &str, kind: u32, vlen: u32, kflag: bool, size_or_type: u32) -> u32 {
            let name_off = self.s(name);
            let info = (u32::from(kflag) << 31) | (kind << 24) | vlen;
            for v in [name_off, info, size_or_type] {
                self.types.extend_from_slice(&v.to_ne_bytes());
            }
            let id = self.next_id;
            self.next_id += 1;
            id
        }
        fn int(&mut self, name: &str, size: u32) -> u32 {
            let id = self.head(name, KIND_INT, 0, false, size);
            self.types.extend_from_slice(&(size * 8).to_ne_bytes());
            id
        }
        fn typedef(&mut self, name: &str, target: u32) -> u32 {
            self.head(name, KIND_TYPEDEF, 0, false, target)
        }
        /// members: (name, type id, raw offset word)
        fn composite(&mut self, name: &str, kind: u32, kflag: bool, members: &[(&str, u32, u32)]) -> u32 {
            // Not a real layout: just a size that tells the structs apart.
            let size = 4 * members.len() as u32;
            let id = self.head(name, kind, members.len() as u32, kflag, size);
            for (m, ty, off) in members {
                let name_off = self.s(m);
                for v in [name_off, *ty, *off] {
                    self.types.extend_from_slice(&v.to_ne_bytes());
                }
            }
            id
        }
        fn finish(self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&MAGIC.to_ne_bytes());
            out.extend_from_slice(&[1, 0]); // version, flags
            out.extend_from_slice(&(HEADER_LEN as u32).to_ne_bytes());
            out.extend_from_slice(&0u32.to_ne_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_ne_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_ne_bytes());
            out.extend_from_slice(&(self.strings.len() as u32).to_ne_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    fn sample() -> Vec<u8> {
        let mut b = Builder::new();
        let int = b.int("int", 4);
        let long = b.int("long", 8);
        let ulong = b.typedef("ulong_t", long);
        // struct { long arg_start; long arg_end; } inside a union, both anonymous.
        let inner = b.composite("", KIND_STRUCT, false, &[("arg_start", long, 0), ("arg_end", long, 64)]);
        let anon_union = b.composite("", KIND_UNION, false, &[("", inner, 0), ("other", int, 0)]);
        let anon_typedef = b.typedef("", anon_union);
        b.composite(
            "mm_struct",
            KIND_STRUCT,
            false,
            &[("count", int, 0), ("total", ulong, 64), ("", anon_typedef, 128)],
        );
        // kflag set: one plain member, one 3-bit bitfield.
        b.composite("flags", KIND_STRUCT, true, &[("plain", int, 32), ("bits", int, (3 << 24) | 64)]);
        // An empty `struct task` precedes the real one, as forward decls do.
        b.composite("task", KIND_STRUCT, false, &[]);
        b.composite("task", KIND_STRUCT, false, &[("pid", int, 96)]);
        b.finish()
    }

    #[test]
    fn finds_plain_typedefed_and_nested_fields() {
        let data = sample();
        let btf = Btf::parse(&data).expect("parse");
        assert_eq!(btf.field_offset("mm_struct", "count"), Ok(0));
        assert_eq!(btf.field_offset("mm_struct", "total"), Ok(8));
        assert_eq!(btf.field_offset("mm_struct", "arg_start"), Ok(16));
        assert_eq!(btf.field_offset("mm_struct", "arg_end"), Ok(24));
        assert_eq!(btf.field_offset("mm_struct", "other"), Ok(16));
        assert_eq!(btf.field_offset("task", "pid"), Ok(12));
        assert_eq!(btf.field_offset("flags", "plain"), Ok(4));
        assert_eq!(btf.struct_size("mm_struct"), Ok(12));
        assert_eq!(btf.struct_size("task"), Ok(4));
        assert_eq!(btf.struct_size("nope"), Err(BtfError::NoSuchStruct("nope".into())));
    }

    #[test]
    fn reports_what_is_missing() {
        let data = sample();
        let btf = Btf::parse(&data).expect("parse");
        assert_eq!(btf.field_offset("nope", "x"), Err(BtfError::NoSuchStruct("nope".into())));
        assert_eq!(
            btf.field_offset("task", "tgid"),
            Err(BtfError::NoSuchField { strukt: "task".into(), field: "tgid".into() })
        );
        assert_eq!(
            btf.field_offset("flags", "bits"),
            Err(BtfError::NotByteAligned { strukt: "flags".into(), field: "bits".into() })
        );
    }

    #[test]
    fn rejects_corrupt_input_without_panicking() {
        let data = sample();
        assert_eq!(Btf::parse(&[]).err(), Some(BtfError::Truncated));
        assert_eq!(Btf::parse(&[0u8; 64]).err(), Some(BtfError::BadMagic));
        // Every truncation either fails to parse or answers without panicking.
        for len in 0..data.len() {
            if let Ok(btf) = Btf::parse(&data[..len]) {
                let _ = btf.field_offset("mm_struct", "arg_end");
            }
        }
        // Flip each byte in turn: same guarantee.
        for i in 0..data.len() {
            let mut bad = data.clone();
            bad[i] ^= 0xff;
            if let Ok(btf) = Btf::parse(&bad) {
                let _ = btf.field_offset("mm_struct", "arg_end");
                let _ = btf.field_offset("task", "pid");
            }
        }
    }
}
