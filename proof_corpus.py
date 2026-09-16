"""The proof-byte corpus: what "parses" means for every standard-library
reader of OpenTimestamps detached proofs in this project, pinned against
the public client (`opentimestamps` 0.4.x) as the independent oracle.

Each case is (name, bytes, verdict, shape, attestations):

  verdict   'parses'   one whole proof by the public client's rules and ours
            'invalid'  refused by both
            'narrowed' the public client reads it; the readers here refuse
                       it by design (an operation a calendar never emits, a
                       varuint longer than ten bytes)
  shape     'linear' (one attestation, no fork) or 'forked'; the linear
            readers refuse every forked case, by design
  attestations  for 'parses': the attestation nodes as (kind, value),
            ('pending', uri), ('bitcoin', height) or ('unknown', tag hex),
            in any order

prefixes() and trailing() derive from every 'parses' case its strict
prefixes and a one-byte extension, all 'invalid'. The same file is carried
by the calendar fork (ops/tests/) and the client adapter; a change to one
is a change to both until the readers are one implementation.
"""

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
DIGEST = bytes(range(32))
URI = b"http://127.0.0.1:14788/"


def vu(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def vb(b):
    return vu(len(b)) + b


def head(digest=DIGEST):
    return MAGIC + b"\x01\x08" + digest


def sha():
    return b"\x08"


def append(x):
    return b"\xf0" + vb(x)


def prepend(x):
    return b"\xf1" + vb(x)


def att(tag, payload):
    return b"\x00" + tag + vb(payload)


def pending(uri=URI):
    return att(PENDING_TAG, vb(uri))


def bitcoin(height):
    return att(BITCOIN_TAG, vu(height))


UNKNOWN_TAG = b"\x01" * 8
P = ("pending", URI.decode())


def cases():
    c = []

    def add(name, data, verdict, shape="linear", attestations=()):
        c.append((name, data, verdict, shape, list(attestations)))

    # Accepted shapes.
    add("pending_minimal", head() + pending(), "parses", "linear", [P])
    add("pending_calendar_shape",
        head() + append(b"\x11" * 16) + sha() + append(b"\x22" * 32) + sha()
        + prepend(b"\x65\x53\xf1\x00") + append(b"\x33" * 8) + pending(),
        "parses", "linear", [P])
    add("bitcoin_linear", head() + append(b"\x44") + sha() + bitcoin(850000), "parses", "linear",
        [("bitcoin", 850000)])
    add("bitcoin_height_zero", head() + bitcoin(0), "parses", "linear", [("bitcoin", 0)])
    add("bitcoin_height_five_byte_varuint", head() + bitcoin(2 ** 32), "parses", "linear",
        [("bitcoin", 2 ** 32)])
    add("forked_pending_and_bitcoin",
        head() + b"\xff" + pending() + append(b"\x44") + sha() + bitcoin(850000),
        "parses", "forked", [P, ("bitcoin", 850000)])
    add("forked_three_branches",
        head() + b"\xff" + pending() + b"\xff" + sha() + bitcoin(1) + bitcoin(2),
        "parses", "forked", [P, ("bitcoin", 1), ("bitcoin", 2)])
    add("nested_fork",
        head() + sha() + b"\xff" + bitcoin(1) + sha() + b"\xff" + pending() + bitcoin(2),
        "parses", "forked", [("bitcoin", 1), P, ("bitcoin", 2)])
    # Distinct heights: the public client keeps attestations in a set, so
    # a thousand identical ones would read back as one.
    add("thousand_forks_one_level",
        head() + b"".join(b"\xff" + bitcoin(1000 + i) for i in range(1000)) + bitcoin(2),
        "parses", "forked", [("bitcoin", 1000 + i) for i in range(1000)] + [("bitcoin", 2)])
    add("unknown_attestation", head() + att(UNKNOWN_TAG, b"\x05\x06"), "parses", "linear",
        [("unknown", UNKNOWN_TAG.hex())])
    add("unknown_attestation_payload_8192", head() + att(UNKNOWN_TAG, b"x" * 8192), "parses", "linear",
        [("unknown", UNKNOWN_TAG.hex())])
    add("uri_empty", head() + pending(b""), "parses", "linear", [("pending", "")])
    add("uri_1000_bytes", head() + pending(b"a" * 1000), "parses", "linear", [("pending", "a" * 1000)])
    add("message_grows_to_4096", head() + append(b"a" * (4096 - 32)) + bitcoin(1), "parses", "linear",
        [("bitcoin", 1)])
    add("message_4096_into_sha256", head() + append(b"a" * (4096 - 32)) + sha() + bitcoin(1), "parses",
        "linear", [("bitcoin", 1)])
    add("ops_255_on_one_path", head() + sha() * 255 + bitcoin(1), "parses", "linear", [("bitcoin", 1)])

    # Full consumption.
    add("bitcoin_payload_trailing_byte", head() + att(BITCOIN_TAG, vu(850000) + b"\x00"), "invalid")
    add("bitcoin_payload_empty", head() + att(BITCOIN_TAG, b""), "invalid")
    add("pending_payload_trailing_byte", head() + att(PENDING_TAG, vb(URI) + b"\x00"), "invalid")
    add("pending_uri_longer_than_payload", head() + att(PENDING_TAG, vu(50) + b"abc"), "invalid")
    add("attestation_payload_8193", head() + att(UNKNOWN_TAG, b"x" * 8193), "invalid")

    # Limits at their boundaries.
    add("uri_1001_bytes", head() + pending(b"a" * 1001), "invalid")
    add("uri_with_space", head() + pending(b"http://x y"), "invalid")
    add("uri_invalid_utf8", head() + pending(b"http://x/\xff"), "invalid")
    add("operand_empty", head() + b"\xf0" + vu(0) + bitcoin(1), "invalid")
    add("operand_4097_bytes", head() + append(b"a" * 4097) + bitcoin(1), "invalid")
    add("message_grows_to_4097", head() + append(b"a" * (4097 - 32)) + bitcoin(1), "invalid")
    add("message_4097_from_two_appends", head() + append(b"a" * (4096 - 32)) + append(b"b") + bitcoin(1), "invalid")
    add("ops_256_on_one_path", head() + sha() * 256 + bitcoin(1), "invalid")

    # Malformed structure.
    add("empty", b"", "invalid")
    add("bad_magic", b"x" * 60, "invalid")
    add("version_2", MAGIC + b"\x02\x08" + DIGEST + bitcoin(1), "invalid")
    add("digest_short", MAGIC + b"\x01\x08" + b"d" * 31, "invalid")
    add("no_attestation", head() + sha(), "invalid")
    add("fork_at_end", head() + b"\xff", "invalid")
    add("fork_then_fork", head() + b"\xff\xff" + pending() + bitcoin(1), "invalid")
    add("fork_without_last_branch", head() + b"\xff" + pending(), "invalid")
    add("unknown_op", head() + b"\x42" + bitcoin(1), "invalid")
    add("attestation_tag_short", head() + b"\x00" + BITCOIN_TAG[:5], "invalid")

    # Narrowings: the public client reads these; the readers here do not.
    add("file_hash_sha1", MAGIC + b"\x01\x02" + b"d" * 20 + bitcoin(1), "narrowed")
    for name, tag in (("op_sha1", b"\x02"), ("op_ripemd160", b"\x03"), ("op_keccak256", b"\x67"),
                      ("op_reverse", b"\xf2"), ("op_hexlify", b"\xf3")):
        add(name + "_in_path", head() + tag + bitcoin(1), "narrowed")
    add("height_in_eleven_byte_varuint", head() + att(BITCOIN_TAG, b"\x80" * 10 + b"\x01"), "narrowed")
    return c


def prefixes():
    """Every strict prefix of every case that parses: all invalid."""
    for name, data, verdict, shape, _ in cases():
        if verdict == "parses":
            for cut in range(len(data)):
                yield "%s[:%d]" % (name, cut), data[:cut]


def trailing():
    """Every case that parses, with one more byte: all invalid."""
    for name, data, verdict, shape, _ in cases():
        if verdict == "parses":
            yield name + "+00", data + b"\x00"
