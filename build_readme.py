#!/usr/bin/env python3
"""Build README.md from README.template.md, injecting machine-captured output.

The "Example output" section is never hand-written: it is captured from a fresh
tool run and pasted byte-for-byte by this script.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    demo = subprocess.run(
        [sys.executable, "secret_timeline.py", "examples/vulnerable.Dockerfile"],
        capture_output=True, text=True, check=True, cwd=HERE,
    )
    example = demo.stdout
    with open(os.path.join(HERE, "..", "built-by-ingenious-ai.md")) as fh:
        built_by = fh.read().rstrip("\n")
    with open(os.path.join(HERE, "README.template.md")) as fh:
        template = fh.read()
    readme = template.replace("{{EXAMPLE_OUTPUT}}", example.rstrip("\n"))
    readme = readme.replace("{{BUILT_BY}}", built_by)
    assert "{{EXAMPLE_OUTPUT}}" not in readme, "EXAMPLE_OUTPUT not replaced"
    assert "{{BUILT_BY}}" not in readme, "BUILT_BY not replaced"
    with open(os.path.join(HERE, "README.md"), "w") as fh:
        fh.write(readme)
    print("README.md written (%d bytes)" % len(readme))


if __name__ == "__main__":
    main()
