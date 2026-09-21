"""The parser corpus against the adapter's two readers and the public
client. proof_corpus.py holds the cases; the library's verdict is
computed here, never assumed. The library is the oracle and the suite
needs it: a host without `opentimestamps` fails these tests instead of
skipping them: the oracle must run."""
import io
import unittest

import api_endpoint as a
import proof_corpus as corpus

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.serialize import StreamDeserializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile


def library_verdict(data):
    """('parses', sorted attestations) or ('invalid', exception name)."""
    try:
        f = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(data)))
    except Exception as exc:
        return "invalid", type(exc).__name__
    out = []
    for _, att in f.timestamp.all_attestations():
        if isinstance(att, PendingAttestation):
            out.append(("pending", att.uri))
        elif isinstance(att, BitcoinBlockHeaderAttestation):
            out.append(("bitcoin", att.height))
        else:
            out.append(("unknown", att.TAG.hex()))
    return "parses", sorted(out, key=repr)


def adapter_verdict(data):
    try:
        _, atts = a.proof_attestations(data)
    except a.OtsError as exc:
        return "invalid", str(exc)
    return "parses", sorted(atts, key=repr)


def linear_verdict(data):
    try:
        proof = a.parse_ots(data)
    except a.OtsError as exc:
        return "invalid", str(exc)
    return "parses", [proof.attestation]


class TestCorpusAgainstTheReaders(unittest.TestCase):
    def test_every_case(self):
        for name, data, verdict, shape, attestations in corpus.cases():
            with self.subTest(name):
                ours = adapter_verdict(data)
                if verdict == "parses":
                    self.assertEqual(ours, ("parses", sorted(attestations, key=repr)))
                    state = a.inspect_proof(data)[0]
                    kinds = {k for k, _ in attestations}
                    expected = (a.BITCOIN_ATTESTATION_PRESENT if "bitcoin" in kinds
                                else a.PENDING if "pending" in kinds else a.INVALID)
                    self.assertEqual(state, expected)
                    linear = linear_verdict(data)
                    if shape == "linear":
                        self.assertEqual(linear, ("parses", attestations))
                    else:
                        self.assertEqual(linear[0], "invalid", "the linear reader refuses forks")
                else:
                    self.assertEqual(ours[0], "invalid", ours)
                    self.assertEqual(linear_verdict(data)[0], "invalid")
                    self.assertEqual(a.inspect_proof(data)[0], a.INVALID)

    def test_every_prefix_and_extension_is_invalid(self):
        for name, data in list(corpus.prefixes()) + list(corpus.trailing()):
            with self.subTest(name):
                self.assertEqual(adapter_verdict(data)[0], "invalid")
                self.assertEqual(linear_verdict(data)[0], "invalid")
                self.assertEqual(a.inspect_proof(data)[0], a.INVALID)


class TestCorpusAgainstTheLibrary(unittest.TestCase):
    def test_parses_and_invalid_agree_with_the_public_client(self):
        for name, data, verdict, shape, attestations in corpus.cases():
            with self.subTest(name):
                lib = library_verdict(data)
                if verdict == "parses":
                    self.assertEqual(lib, ("parses", sorted(attestations, key=repr)))
                elif verdict == "invalid":
                    self.assertEqual(lib[0], "invalid", lib)
                else:
                    self.assertEqual(lib[0], "parses", "a narrowing is something the client reads: " + repr(lib))
                    self.assertEqual(adapter_verdict(data)[0], "invalid")

    def test_prefixes_and_extensions_agree(self):
        for name, data in list(corpus.prefixes()) + list(corpus.trailing()):
            with self.subTest(name):
                self.assertEqual(library_verdict(data)[0], "invalid")

    def test_every_attestation_type_the_client_knows_is_read_as_the_client_reads_it(self):
        """The Litecoin and Ethereum tags are known to the client and read
        as one varuint height; readers that took them for opaque unknown
        tags would parse a payload the client refuses (empty, a trailing
        byte), and beside a Bitcoin node make the proof
        bitcoin_attestation_present. For each of the four
        tags: a valid payload, an empty one, a trailing byte, an
        unterminated varuint; alone for both readers and inspect_proof,
        beside a Bitcoin node for the tree reader and inspect_proof (the
        linear reader refuses every fork by design). The verdict is the
        library's, computed here. A valid Litecoin or Ethereum payload
        alone is no usable attestation: INVALID, not PENDING and not
        bitcoin_attestation_present."""
        tags = (("pending", corpus.PENDING_TAG, corpus.vb(corpus.URI), a.PENDING),
                ("bitcoin", corpus.BITCOIN_TAG, corpus.vu(7), a.BITCOIN_ATTESTATION_PRESENT),
                ("litecoin", corpus.LITECOIN_TAG, corpus.vu(7), a.INVALID),
                ("ethereum", corpus.ETHEREUM_TAG, corpus.vu(7), a.INVALID))
        for name, tag, valid, alone_state in tags:
            for shape, payload in (("valid", valid), ("empty", b""), ("trailing", valid + b"\x00"), ("unterminated", b"\x80")):
                alone = corpus.head() + corpus.att(tag, payload)
                beside = corpus.head() + b"\xff" + corpus.att(tag, payload) + corpus.append(b"\x44") + corpus.sha() + corpus.bitcoin(850000)
                with self.subTest(tag=name, payload=shape):
                    lib = library_verdict(alone)
                    self.assertEqual(lib[0], "parses" if shape == "valid" else "invalid", lib)
                    self.assertEqual(adapter_verdict(alone)[0], lib[0], adapter_verdict(alone))
                    self.assertEqual(linear_verdict(alone)[0], lib[0], linear_verdict(alone))
                    self.assertEqual(adapter_verdict(beside)[0], library_verdict(beside)[0])
                    self.assertEqual(linear_verdict(beside)[0], "invalid", "the linear reader refuses forks")
                    if shape == "valid":
                        self.assertEqual(adapter_verdict(alone), lib)
                        self.assertEqual(a.inspect_proof(alone)[0], alone_state)
                        self.assertEqual(a.inspect_proof(beside)[0], a.BITCOIN_ATTESTATION_PRESENT)
                    else:
                        self.assertEqual(a.inspect_proof(alone)[0], a.INVALID)
                        self.assertEqual(a.inspect_proof(beside)[0], a.INVALID, "a refused payload beside a Bitcoin node is not a proof")


if __name__ == "__main__":
    unittest.main(verbosity=2)
