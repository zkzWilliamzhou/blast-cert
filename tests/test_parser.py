import unittest

from blast.expand import expand_word
from blast.lexer import lex
from blast.model import WORD_DYNAMIC, WORD_LITERAL
from blast.parser import parse


class ParserTests(unittest.TestCase):
    def test_redirect_target_and_fd(self):
        model = parse("cat 2> err.txt")
        redirect = model.pipelines[0].commands[0].redirects[0]
        self.assertEqual(redirect.op, ">")
        self.assertEqual(redirect.fd, 2)
        self.assertEqual(redirect.target.value, "err.txt")

    def test_pipeline_stages(self):
        model = parse("curl -s x | sh")
        self.assertEqual(len(model.pipelines[0].commands), 2)
        self.assertTrue(model.invocations[1].pipe_in)

    def test_assignments(self):
        model = parse("FOO=bar ls")
        self.assertEqual(model.pipelines[0].commands[0].assignments, ("FOO=bar",))

    def test_double_dash_is_preserved_for_the_evaluator(self):
        model = parse("rm -- --help")
        self.assertEqual([a.value for a in model.invocations[0].args],
                         ["--", "--help"])

    def test_background(self):
        model = parse("sleep 1 &")
        self.assertTrue(model.invocations[0].background)

    def test_dynamic_command_name(self):
        model = parse("$cmd -rf /")
        self.assertEqual(model.invocations[0].name.state, WORD_DYNAMIC)

    def test_expand_with_trusted_env_only(self):
        word = [t.word for t in lex("$TARGET").tokens if t.word][0]
        self.assertEqual(word.state, WORD_DYNAMIC)
        expanded = expand_word(word, {"TARGET": "/tmp/x"})
        self.assertEqual(expanded.state, WORD_LITERAL)
        self.assertEqual(expanded.value, "/tmp/x")
        self.assertEqual(expanded.provenance, "trusted-env")

    def test_unknown_variable_is_never_half_expanded(self):
        word = [t.word for t in lex("$TARGET/file").tokens if t.word][0]
        expanded = expand_word(word, {})
        self.assertEqual(expanded.state, WORD_DYNAMIC)
        self.assertIsNone(expanded.value)

    def test_parameter_expansion_with_default_is_not_guessed(self):
        word = [t.word for t in lex("${TARGET:-/etc/passwd}").tokens if t.word][0]
        expanded = expand_word(word, {"TARGET": "/tmp/x"})
        self.assertEqual(expanded.state, WORD_DYNAMIC)

    def test_subshell_is_outside_subset(self):
        model = parse("(rm -rf /)")
        self.assertTrue(any(i.code == "UNSUPPORTED_SUBSHELL" for i in model.issues))


if __name__ == "__main__":
    unittest.main()
