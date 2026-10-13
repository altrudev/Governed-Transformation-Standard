import pathlib
import unittest
PATH=pathlib.Path(__file__).resolve().parents[1]/"docs"/"TECHNICAL-TERMINOLOGY-CROSSWALK.md"
class GlossaryTests(unittest.TestCase):
    def test_crosswalk_has_explicit_conformance_disclaimer(self):
        content=PATH.read_text()
        self.assertIn("not certification",content)
        for term in ("Authority Envelope","Capability Lattice","Policy IR","Guardian","Independent Assurance Fabric","Challenge authority","GTS","Frequency","DDC"):
            self.assertIn(term,content)
