import unittest

from blast.lexer import lex
from blast.model import WORD_LITERAL, WORD_OPAQUE


class LexerTests(unittest.TestCase):
    def words(self, source):
        return [t.word for t in lex(source).tokens if t.kind == "word" and t.word]

    def test_quote_removal_and_empty_quotes_are_flagged(self):
        words = self.words("r''m -rf /tmp/x")
        self.assertEqual(words[0].value, "rm")
        self.assertEqual(words[0].state, WORD_LITERAL)
        self.assertTrue(words[0].obfuscated)

    def test_escape_hides_command_name(self):
        words = self.words("r\\m -rf /tmp/x")
        self.assertEqual(words[0].value, "rm")
        self.assertTrue(words[0].obfuscated)

    def test_ansi_c_quote_is_decoded_and_flagged(self):
        words = self.words("$'\\x72\\155' -rf /tmp/x")
        self.assertEqual(words[0].value, "rm")
        self.assertTrue(words[0].obfuscated)

    def test_operators(self):
        tokens = lex("curl -s x | sh").tokens
        self.assertIn("|", [t.text for t in tokens if t.kind == "operator"])

    def test_command_substitution_part(self):
        words = self.words("echo $(id)")
        self.assertTrue(any(p.kind == "command_substitution" for p in words[-1].parts))

    def test_backtick_part(self):
        words = self.words("echo `id`")
        self.assertTrue(any(p.kind == "backtick" for p in words[-1].parts))

    def test_process_substitution_is_opaque(self):
        words = self.words("bash <(curl -s x)")
        self.assertEqual(words[1].state, WORD_OPAQUE)
        self.assertTrue(any(p.kind == "process_substitution" for p in words[1].parts))

    def test_unterminated_quote_is_error(self):
        result = lex("echo 'unterminated")
        self.assertTrue(any(i.code == "UNTERMINATED_QUOTE" for i in result.issues))

    def test_invisible_zero_width_is_rejected(self):
        result = lex("echo\u200bhi")
        self.assertTrue(any(i.code == "INVISIBLE_CHARACTER" for i in result.issues))

    def test_cr_and_nul_are_rejected(self):
        for source in ("echo hi\r", "echo\x00hi"):
            result = lex(source)
            self.assertTrue(any(i.code == "INVISIBLE_CHARACTER" for i in result.issues))

    def test_comment_token(self):
        tokens = lex("echo hi # hidden").tokens
        self.assertTrue(any(t.kind == "comment" for t in tokens))

    def test_line_continuation(self):
        words = self.words("echo hi\\\nthere")
        self.assertEqual([w.value for w in words], ["echo", "hi", "there"])

    def test_input_budget(self):
        from blast.model import Budget
        result = lex("a" * 100, budget=Budget(max_input_bytes=10))
        self.assertTrue(any(i.code == "INPUT_TOO_LARGE" for i in result.issues))

    def test_unsupported_dialect(self):
        result = lex("ls", dialect="fish")
        self.assertTrue(any(i.code == "UNSUPPORTED_DIALECT" for i in result.issues))

    def test_empty_command_is_error(self):
        result = lex("")
        self.assertTrue(any(i.code == "EMPTY_COMMAND" for i in result.issues))

    def test_word_only_token_budget(self):
        from blast.model import Budget
        result = lex("a b c d e f g h", budget=Budget(max_tokens=5))
        self.assertTrue(any(i.code == "TOKEN_BUDGET" for i in result.issues))
        self.assertLessEqual(len(result.tokens), 6)


if __name__ == "__main__":
    unittest.main()
