# -*- coding: utf-8 -*-
"""Mechanical mutants of C# sources - which ones a sweep plants, one at a time.

The catalogue of DNSConformanceTests' build/mutation/genmut.py, whose reasons
hold here too: Stryker.NET has not run on this family's code, and the
operators that a regular expression applies to C# without understanding it are
most of the value and none of the ceremony. Three are added, for the way the
PKI's ACME code is written: `is null` and `is not null` turned into each other,
and a negation taken away - the "if (!jws.SignedBy(jwk)) throw" a server stands
on. "<" and ">" are taken with a blank before them alone, so that the angle
brackets of a generic type - "List<String> x" - are not planted with mutants
that only the compiler sees.

This module only lists mutants. Running them is sweep.py's job.

    python build/mutation/genmut.py libs/PKI/PKI/Enrollment/ACMEJWS.cs
"""

import io
import re
import sys

# (name, pattern, replacement) - applied to one occurrence at a time.
OPERATORS = [
    ("logical-and-to-or",      r"&&",                       "||"),
    ("logical-or-to-and",      r"\|\|",                     "&&"),
    ("equality-to-inequality", r"(?<![=!<>])== ",           "!= "),
    ("inequality-to-equality", r"!= ",                      "== "),
    ("less-to-less-or-equal",  r"(?<= )< ",                 "<= "),
    ("greater-to-ge",          r"(?<= )> ",                 ">= "),
    ("le-to-less",             r"<= ",                      "< "),
    ("ge-to-greater",          r">= ",                      "> "),
    ("true-to-false",          r"\btrue\b",                 "false"),
    ("false-to-true",          r"\bfalse\b",                "true"),
    ("is-null-to-is-not-null", r"\bis null\b",              "is not null"),
    ("is-not-null-to-is-null", r"\bis not null\b",          "is null"),
    ("negation-removed",       r"(?<![!=<>\w)\]])!(?=[A-Za-z_(@])", ""),
]

COMMENT = re.compile(r"^\s*(//|/\*|\*)")


def is_code(line):
    """Comment lines, and lines that are a string and nothing else, are left alone."""
    if COMMENT.match(line):
        return False
    without_strings = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
    return without_strings.strip() not in ("", '""')


def strip_strings(line):
    """String contents blanked, so that offsets stay and nothing inside a literal is found."""
    def blank(m):
        return '"' + " " * (len(m.group(0)) - 2) + '"'
    return re.sub(r'"(?:[^"\\]|\\.)*"', blank, line)


def mutants_for(path, rel):
    """Every mutant of the file: (file, line number, operator, line, mutated line)."""

    out   = []
    lines = io.open(path, encoding="utf-8-sig").read().replace("\r\n", "\n").split("\n")

    for number, line in enumerate(lines, start=1):

        if not is_code(line):
            continue

        searchable = strip_strings(line)

        for name, pattern, replacement in OPERATORS:
            for match in re.finditer(pattern, searchable):
                start, end = match.span()
                mutated    = line[:start] + replacement + line[end:]
                if mutated != line:
                    out.append((rel, number, name, line, mutated))

    return out


if __name__ == "__main__":

    total = 0

    for path in sys.argv[1:]:
        mutants = mutants_for(path, path)
        total  += len(mutants)
        byop    = {}
        for _, _, op, _, _ in mutants:
            byop[op] = byop.get(op, 0) + 1
        print("%-60s %5d   %s" % (path, len(mutants), ", ".join("%s %d" % kv for kv in sorted(byop.items(), key=lambda kv: -kv[1]))))

    print("%-60s %5d" % ("all", total))
