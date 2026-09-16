"""A stdlib reader for the two things calibration needs from a font file: its PostScript
name and the codepoints its cmap maps. ROADMAP O189, V3. It reads no glyph and no metric;
the advance table comes from gen_advances.py and fontTools, never from here.

A TrueType collection (.ttc) holds several faces; `faces()` lists each face's table
directory offset, and every other function takes one of those offsets. A malformed file
raises ValueError naming what was wrong, so a caller cannot mistake a parse failure for
an empty answer.
"""
import struct


def _u16(data, off):
    return struct.unpack_from(">H", data, off)[0]


def _u32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def faces(data):
    """[table directory offset] for every face: one for a font file, several for a .ttc."""
    if len(data) < 12:
        raise ValueError("%d bytes is too short for a font" % len(data))
    tag = data[:4]
    if tag == b"ttcf":
        count = _u32(data, 8)
        if count == 0 or 12 + 4 * count > len(data):
            raise ValueError("a collection header declaring %d faces" % count)
        return [_u32(data, 12 + 4 * i) for i in range(count)]
    if tag in (b"\x00\x01\x00\x00", b"OTTO", b"true"):
        return [0]
    raise ValueError("unknown sfnt tag %r" % tag)


def tables(data, face):
    """{tag: (offset, length)} for one face."""
    count = _u16(data, face + 4)
    out = {}
    for i in range(count):
        rec = face + 12 + 16 * i
        if rec + 16 > len(data):
            raise ValueError("a table directory running past the end of the file")
        tag = data[rec:rec + 4].decode("latin-1")
        offset, length = _u32(data, rec + 8), _u32(data, rec + 12)
        if offset + length > len(data):
            raise ValueError("table %s running past the end of the file" % tag)
        out[tag] = (offset, length)
    return out


def ps_name(data, face):
    """The face's PostScript name (name ID 6): Windows Unicode first, then Macintosh Roman."""
    t = tables(data, face)
    if "name" not in t:
        raise ValueError("no name table")
    base, _ = t["name"]
    count, strings = _u16(data, base + 2), base + _u16(data, base + 4)
    found = {}
    for i in range(count):
        rec = base + 6 + 12 * i
        platform, encoding, language, name_id, length, offset = struct.unpack_from(">HHHHHH", data, rec)
        if name_id != 6:
            continue
        raw = data[strings + offset:strings + offset + length]
        if platform == 3 and encoding in (0, 1):
            found.setdefault(0 if language == 0x409 else 1, raw.decode("utf-16-be"))
        elif platform == 1 and encoding == 0:
            found.setdefault(2, raw.decode("latin-1"))
    if not found:
        raise ValueError("no PostScript name (name ID 6)")
    return found[min(found)]


def codepoints(data, face):
    """Every codepoint the face's Unicode cmap maps to a glyph other than .notdef."""
    t = tables(data, face)
    if "cmap" not in t:
        raise ValueError("no cmap table")
    base, _ = t["cmap"]
    subtables = {}
    for i in range(_u16(data, base + 2)):
        platform, encoding, offset = struct.unpack_from(">HHI", data, base + 4 + 8 * i)
        subtables[(platform, encoding)] = base + offset
    for key in ((3, 10), (0, 6), (0, 4), (3, 1), (0, 3)):
        if key not in subtables:
            continue
        off = subtables[key]
        fmt = _u16(data, off)
        if fmt == 12:
            return _format12(data, off)
        if fmt == 4:
            return _format4(data, off)
    raise ValueError("no Unicode cmap subtable in format 4 or 12 (have %s)" % sorted(subtables))


def _format12(data, off):
    out = set()
    for i in range(_u32(data, off + 12)):
        start, end, glyph = struct.unpack_from(">III", data, off + 16 + 12 * i)
        for cp in range(start, end + 1):
            if glyph + (cp - start):
                out.add(cp)
    return out


def _format4(data, off):
    segs = _u16(data, off + 6) // 2
    ends = off + 14
    starts = ends + 2 * segs + 2
    deltas = starts + 2 * segs
    ranges = deltas + 2 * segs
    out = set()
    for s in range(segs):
        end, start = _u16(data, ends + 2 * s), _u16(data, starts + 2 * s)
        delta, range_offset = _u16(data, deltas + 2 * s), _u16(data, ranges + 2 * s)
        for cp in range(start, end + 1):
            if cp == 0xFFFF:
                continue
            if range_offset == 0:
                glyph = (cp + delta) & 0xFFFF
            else:
                at = ranges + 2 * s + range_offset + 2 * (cp - start)
                glyph = _u16(data, at)
                if glyph:
                    glyph = (glyph + delta) & 0xFFFF
            if glyph:
                out.add(cp)
    return out
