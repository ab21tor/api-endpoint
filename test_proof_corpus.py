"""The parser corpus against the adapter's two readers and the public
client. proof_corpus.py holds the cases; the library's verdict is
computed here, never assumed. Skipped, and said so, only when the
opentimestamps package is not importable."""
import io
import unittest

import api_endpoint as a
import proof_corpus as corpus

try:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
    LIBRARY = True
except ImportError:      # pragma: no cover - the appliance host may not have it
    LIBRARY = False


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


@unittest.skipUnless(LIBRARY, "opentimestamps is not importable: the oracle comparison did not run")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
