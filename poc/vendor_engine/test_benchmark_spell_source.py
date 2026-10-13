"""LogPai Spell is evaluated at source byte spans, not grouping F1."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from benchmark_spell_source import match_tokenized_template,evaluate,SOURCE_COMMIT
from residual_miner import ROOT,SAMPLE_SHA


class SpellCandidateTests(unittest.TestCase):
    def test_token_aligner_returns_original_positions(self):
        raw="prefix: User alice logged in from bob securely"
        body="User alice logged in from bob securely"
        values=match_tokenized_template(
            "User <*> logged in from <*> securely",
            raw,body,raw.index(body)
        )
        self.assertIsNotNone(values)
        self.assertEqual(["alice","bob"],[
            raw.encode("utf8")[a:b].decode("utf8")
            for a,b in values
        ])

    def test_repeated_anchor_ambiguity_and_unbounded_masks_abstain(self):
        raw="User alice logged in from bob securely"
        self.assertIsNone(match_tokenized_template("User <*> <*> securely",
                                                    raw,raw,0))
        self.assertIsNone(match_tokenized_template("<*>",raw,raw,0))
        self.assertIsNone(match_tokenized_template("Other <*> securely",
                                                    raw,raw,0))

    @unittest.skipUnless(all((ROOT/name).is_file() for name in SAMPLE_SHA)
                         and (ROOT.parent/"logparser"/"logparser"/"Spell"/"Spell.py").is_file(),
                         "Isolated optional research sources not installed")
    def test_true_span_gold_rejects_spell_for_this_corpus(self):
        try:
            import pandas,regex
        except ImportError:
            self.skipTest("Optional isolated Spell dependencies missing")
        m=evaluate()
        self.assertEqual(1581,m["holdout_records"])
        self.assertEqual(SOURCE_COMMIT,m["source_sha"])
        self.assertEqual("REJECTED_FOR_UNLABELED_SOURCE_VARIABLE_EXTRACTION",
                         m["adoption"])
        self.assertLess(m["exact_variable_span"]["f1"],0.3762)
        self.assertGreater(m["exact_variable_span"]["FP"],1000)
        self.assertTrue(m["not_a_semantic_dictionary_test"])
        self.assertFalse(m["native_or_stellar_verified"])


if __name__=="__main__":
    unittest.main()
