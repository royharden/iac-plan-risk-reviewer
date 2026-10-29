"""Independent frozen-format byte builder. No candidate imports."""
import hashlib
import struct

HEADER = struct.Struct(">8sHBBHH32s32s")
FRAME = struct.Struct(">BBBBQQ32s")
TRAILER = struct.Struct(">8sHQ32s")


def split(raw):
    header = HEADER.unpack(raw[:80])
    cursor = 80
    records = []
    for _ in range(23):
        rid, state, reason, known, logical, retained, digest = FRAME.unpack(raw[cursor:cursor + 52])
        cursor += 52
        payload = raw[cursor:cursor + retained]
        cursor += retained
        records.append((rid, state, reason, logical if known else None, payload))
    return header, records


def build(header, records):
    output = bytearray(HEADER.pack(*header))
    for rid, state, reason, logical, payload in records:
        digest = hashlib.sha256(payload).digest() if state in (1, 2) else bytes(32)
        output.extend(FRAME.pack(rid, state, reason, int(logical is not None),
                                 logical or 0, len(payload), digest))
        output.extend(payload)
    output.extend(TRAILER.pack(b"M4END02\n", 23, len(output), hashlib.sha256(output).digest()))
    return bytes(output)
