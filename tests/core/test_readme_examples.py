import doctest
import re


def extract_doctests(md_content):
    """Extract Python code blocks that appear to be doctests."""
    # This regex matches code blocks that start with '```python' and end with '```'
    code_blocks = re.findall(r"```python(.*?)```", md_content, re.DOTALL)
    # Concatenate all code blocks into a single string of code
    return "\n\n".join(code_blocks)


def run_doctests(code):
    """Run doctests in the given block of code."""
    parser = doctest.DocTestParser()
    test = parser.get_doctest(code, {}, "extracted_doctests", "extracted", 0)
    runner = doctest.DocTestRunner()
    runner.run(test)


with open("README.md") as f:
    markdown_content = f.read()

code_to_test = extract_doctests(markdown_content)
run_doctests(code_to_test)


def test_readme_examples():
    run_doctests(code_to_test)
