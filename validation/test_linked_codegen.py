"""Regression checks for toolchain-dependent symbol spelling in final-link review."""
import unittest

from linked_codegen import functions


class SymbolParsingTests(unittest.TestCase):
    def names(self, symbol):
        assembly = f"0000000000000000 <{symbol}>:\n   0:\tc3\tret\n"
        return [name for name, _ in functions(assembly)]

    def test_demangled_tag_is_required(self):
        self.assertEqual(self.names("post_quantum_core::symmetric::tag"),
                         ["post_quantum_core::symmetric::tag"])

    def test_llvm_suffixed_legacy_tag_is_required(self):
        self.assertEqual(
            self.names("_ZN17post_quantum_core9symmetric3tag17ha209f6a1a54c78baE.llvm.5675181201873938032"),
            ["post_quantum_core::symmetric::tag"],
        )

    def test_unrelated_symbol_is_not_accepted(self):
        self.assertEqual(self.names("_ZN17post_quantum_core9symmetric4tags17ha209f6a1a54c78baE"), [])


if __name__ == "__main__":
    unittest.main()
