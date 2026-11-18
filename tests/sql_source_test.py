"""Regression checks for finding the actual Rust functions and SQL strings."""
import unittest

from sql_source import extract_function, rust_strings, source


class SqlSourceReader(unittest.TestCase):
    def test_function_boundaries_ignore_literals_comments_and_nested_functions(self):
        rust = r'''
// fn query() { panic!("not a function"); }
impl Store {
    pub fn query<'a>(value: &'a str) -> &'a str {
        let json = r##"{ "fn query()": "}" }"##;
        let closing = '}'; // }
        /* fn query() { } */
        fn nested() { let value = "}"; }
        if true { nested(); }
        "SELECT first"
    }
    fn next() { "DELETE next"; }
}
'''
        found = extract_function(rust, "query")
        self.assertIn('"SELECT first"', found)
        self.assertNotIn('DELETE next', found)
        self.assertEqual(list(rust_strings(found))[-1], "SELECT first")

    def test_missing_and_duplicate_functions_fail_instead_of_picking_one(self):
        for rust in ["fn other() {}", "impl A {fn query() {}} impl B {fn query() {}}"]:
            with self.assertRaisesRegex(AssertionError, "Expected one"):
                extract_function(rust, "query", "fixture.rs")
        with self.assertRaisesRegex(AssertionError, "Unclosed"):
            extract_function("fn query() {", "query")

    def test_declarations_do_not_capture_the_following_function(self):
        rust = 'trait Store { fn query(); fn other() { "DELETE unrelated"; } }'
        with self.assertRaisesRegex(AssertionError, "Missing function body"):
            extract_function(rust, "query")
        self.assertIn('"SELECT array"', extract_function(
            'fn query() -> [u8; 8] { "SELECT array"; [0; 8] }', "query"))

    def test_strings_preserve_raw_and_rust_escape_forms(self):
        rust = r'''r"raw\path" r###"SELECT '{raw}'"### "line\n\u{1F680}\x41\'\"\\\0"'''
        self.assertEqual(list(rust_strings(rust)), ["raw\\path", "SELECT '{raw}'", 'line\n🚀A\'"\\\0'])
        self.assertEqual(list(rust_strings('"SELECT \\\n    value"')), ["SELECT value"])

    def test_comment_strings_and_char_literals_are_not_sql(self):
        rust = '''// "DELETE comment"
/* "INSERT comment" */
let c = '{'; let query = "SELECT real";
'''
        self.assertEqual(list(rust_strings(rust)), ["SELECT real"])
        nested = '/* outer /* nested */ "DELETE hidden" */ fn query() {}'
        with self.assertRaisesRegex(AssertionError, "Nested Rust block comments"):
            list(rust_strings(nested))
        with self.assertRaisesRegex(AssertionError, "Nested Rust block comments"):
            extract_function(nested, "query")

    def test_unknown_source_requires_explicit_registration(self):
        with self.assertRaisesRegex(AssertionError, "Unregistered SQL source"):
            source("../unregistered")
