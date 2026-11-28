# -*- coding: utf-8 -*-
"""The mutation sweep of the PKI's ACME server: what the suite would notice.

One mutant at a time (genmut.py) is planted into a file of the PKI, the block's
judge - the cheapest test project that exercises it - is built and run, and the
verdict recorded: KILLED where a test failed, SURVIVED where none did. A
survivor is a line nothing in the suite is watching - or a mutation that
changes nothing (an equivalent mutant), which only reading it tells apart.
MUTATION.md has what the sweeps found.

    python build/mutation/sweep.py jws
    python build/mutation/sweep.py api 40          stop after 40 mutants
    python build/mutation/sweep.py jws --survivors pass 2: the survivors of pass 1
                                                   again, against the tests since

Pass 2 is how a gap is closed: a test written for a survivor, and the
survivor planted again - killed now, or still a gap.

The harness of DNSConformanceTests' sweep_folder.py, with its lessons kept:
a guard that the assembly the judge loads was rebuilt, a build that failed
without a compiler error stops the sweep instead of being recorded as the
mutant's, a test run that hangs is killed with its tree, results are appended
as they come and a rerun skips what is recorded. One thing is new: the sweep
runs in a mirror of the repository (PKICONFORMANCE_MUTATION_TREE, by default
in the temporary directory), synced before it starts, so that the checkout
stays usable for the hours a block takes and no mutant is ever left in
libs/PKI.

The judge's fuzzer runs 20 requests per case instead of 200
(PKICONFORMANCE_FUZZ_ITERATIONS): seeded as ever, cheaper per mutant.
"""

import filecmp
import io
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import genmut

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
TREE = os.environ.get("PKICONFORMANCE_MUTATION_TREE") or os.path.join(tempfile.gettempdir(), "pkiconformance-mutation-tree")

# Every block of the PKI's ACME code, and its judge.
BLOCKS = {
    "jws":       dict(files=[r"libs\PKI\PKI\Enrollment\ACMEJWS.cs"],       judge="Server"),
    "api":       dict(files=[r"libs\PKI\PKI\HTTPAPI\PKIHTTPAPI.ACME.cs"],  judge="Server"),
    "state":     dict(files=[r"libs\PKI\PKI\Enrollment\ACMEState.cs"],     judge="Server"),
    "validator": dict(files=[r"libs\PKI\PKI\Enrollment\ACMEValidator.cs"], judge="Validation"),
}

SKIPPED_DIRECTORIES = { ".git", "bin", "obj", "artifacts", "node_modules", "TestResults", ".vs" }

ENVIRONMENT = dict(os.environ,
                   DOTNET_CLI_UI_LANGUAGE        = "en",
                   VSLANG                        = "1033",
                   DOTNET_NOLOGO                 = "1",
                   PKICONFORMANCE_FUZZ_ITERATIONS = "20")

# "Total tests: 241", and "Failed: 2" only where some failed.
FAILED         = re.compile(r"^\s*Failed:\s*(\d+)", re.MULTILINE)
TOTAL          = re.compile(r"Total tests:\s*(\d+)")
FAILED_TEST    = re.compile(r"^\s*Failed (.+?) \[", re.MULTILINE)
COMPILER_ERROR = re.compile(r": error CS[0-9]+", re.IGNORECASE)
TIMED_OUT      = -9
TIMEOUT        = object()

# -nodeReuse:false: MSBuild's reusable nodes outlive the build and keep handles
# on what they wrote; a sweep runs hundreds of builds of the same outputs.
BUILD_FLAGS    = [ "-v", "q", "--nologo", "-nodeReuse:false" ]
TEST_FILTER    = [ "--filter", "TestCategory!=KnownIssue&TestCategory!=ToDo" ]


#region Mirror

def sync_mirror():
    """The repository's sources into the mirror - files that differ copied,
    files gone taken away - leaving the mirror's build outputs alone."""

    copied = 0

    for directory, subdirectories, files in os.walk(REPO):

        subdirectories[:] = [ d for d in subdirectories if d not in SKIPPED_DIRECTORIES ]
        relative = os.path.relpath(directory, REPO)
        target   = os.path.join(TREE, relative)
        os.makedirs(target, exist_ok=True)

        for name in files:
            if name == ".git":
                continue
            source      = os.path.join(directory, name)
            destination = os.path.join(target, name)
            if not os.path.exists(destination) or not filecmp.cmp(source, destination, shallow=False):
                shutil.copy2(source, destination)
                copied += 1

    for directory, subdirectories, files in os.walk(TREE):
        subdirectories[:] = [ d for d in subdirectories if d not in SKIPPED_DIRECTORIES ]
        relative = os.path.relpath(directory, TREE)
        for name in files:
            if not os.path.exists(os.path.join(REPO, relative, name)):
                os.remove(os.path.join(directory, name))

    return copied

#endregion

#region Processes

def kill_tree(pid):
    """Windows does not take a process's children down with it, and dotnet test
    leaves a testhost behind holding the pipe."""
    if os.name == "nt":
        subprocess.run([ "taskkill", "/T", "/F", "/PID", str(pid) ], capture_output=True)
    else:
        os.killpg(os.getpgid(pid), signal.SIGKILL)


def run(command, timeout=1800):

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               encoding="utf-8", errors="replace", env=ENVIRONMENT, cwd=TREE)
    try:
        out, err = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, out, err)
    except subprocess.TimeoutExpired:
        kill_tree(process.pid)
        try:
            out, err = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        return subprocess.CompletedProcess(command, TIMED_OUT, out, err)


def project(judge):
    return os.path.join(TREE, "conformance", "PKIConformance.ACME.%s.Tests" % judge, "PKIConformance.ACME.%s.Tests.csproj" % judge)


def guard(judge):
    """The PKI the judge loads - which a mutant's build has to have rewritten."""
    return os.path.join(TREE, "conformance", "PKIConformance.ACME.%s.Tests" % judge, "bin", "Debug", "net11.0", "PKI.dll")


def build(judge):
    return run([ "dotnet", "build", project(judge) ] + BUILD_FLAGS)


def test(judge, timeout=1800):
    """(failed, total, the first failed tests) - TIMEOUT, or None where there is no summary."""

    result = run([ "dotnet", "test", project(judge), "--no-build", "--nologo", "--logger", "console;verbosity=normal" ] + TEST_FILTER,
                 timeout=timeout)

    if result.returncode == TIMED_OUT:
        return TIMEOUT

    out = result.stdout or ""
    failed, total = FAILED.search(out), TOTAL.search(out)

    return (int(failed.group(1)) if failed else 0, int(total.group(1)), FAILED_TEST.findall(out)[:3]) if total else None

#endregion

#region Files

def read(path):
    raw  = open(path, "rb").read()
    bom  = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig" if bom else "utf-8")
    return text, ("\r\n" if "\r\n" in text else "\n"), bom


def write(path, text, newline, bom):
    data = text.replace("\r\n", "\n").replace("\n", newline).encode("utf-8")
    open(path, "wb").write((b"\xef\xbb\xbf" if bom else b"") + data)

#endregion


def pki_commit():
    return subprocess.run([ "git", "-C", os.path.join(REPO, "libs", "PKI"), "rev-parse", "--short=8", "HEAD" ],
                          capture_output=True, text=True).stdout.strip()


def pki_is_clean():
    return subprocess.run([ "git", "-C", os.path.join(REPO, "libs", "PKI"), "status", "--porcelain" ],
                          capture_output=True, text=True).stdout.strip() == ""


def main():

    if len(sys.argv) < 2 or sys.argv[1] not in BLOCKS:
        sys.exit("usage: sweep.py <%s> [limit] [--survivors]" % "|".join(BLOCKS))

    name    = sys.argv[1]
    again   = "--survivors" in sys.argv[2:]
    numbers = [ argument for argument in sys.argv[2:] if argument.isdigit() ]
    limit   = int(numbers[0]) if numbers else 0
    block   = BLOCKS[name]
    judge   = block["judge"]

    if not pki_is_clean():
        sys.exit("libs/PKI has changes of its own: a sweep measures a commit, and this is none.")

    commit  = pki_commit()
    first   = os.path.join(HERE, "results", "%s-%s.tsv" % (name, commit))
    results = first[:-len(".tsv")] + "-pass2.tsv" if again else first
    os.makedirs(os.path.dirname(results), exist_ok=True)

    # Pass 2 plants the survivors of pass 1 alone.
    survivors = set()
    if again:
        if not os.path.exists(first):
            sys.exit("no pass 1 of the block at this commit: " + first)
        for line in io.open(first, encoding="utf-8"):
            fields = line.rstrip("\n").split("\t")
            if len(fields) >= 6 and fields[3] == "SURVIVED":
                survivors.add((fields[0], fields[1], fields[2], fields[5]))

    print("block   %s (%s)" % (name, ", ".join(block["files"])))
    print("PKI     %s" % commit)
    print("judge   PKIConformance.ACME.%s.Tests" % judge)
    print("mirror  %s - %d files synced" % (TREE, sync_mirror()))
    print(flush=True)

    built = build(judge)
    if built.returncode != 0:
        sys.exit("the baseline does not build:\n" + ((built.stdout or "") + (built.stderr or ""))[-3000:])

    started  = time.time()
    baseline = test(judge)
    seconds  = time.time() - started

    if baseline is TIMEOUT or baseline is None:
        sys.exit("the baseline's judge gave no summary")
    if baseline[0] != 0:
        sys.exit("the baseline is not clean: %d of %d failed (%s)" % (baseline[0], baseline[1], ", ".join(baseline[2])))

    # A mutant that hangs costs ten times the clean run, not half an hour.
    timeout = max(180, int(seconds * 10))

    print("baseline: %d tests, none failed, in %.0f s - a mutant gets %d s" % (baseline[1], seconds, timeout), flush=True)

    mutants = []
    for file in block["files"]:
        mutants.extend(genmut.mutants_for(os.path.join(TREE, file), file.replace("\\", "/")))

    done = set()
    if os.path.exists(results):
        for line in io.open(results, encoding="utf-8"):
            fields = line.rstrip("\n").split("\t")
            if len(fields) >= 6:
                done.add((fields[0], fields[1], fields[2], fields[5]))

    print("%d mutants, %d recorded already\n" % (len(mutants), len(done)), flush=True)

    occurrences, counts, ran = {}, {}, 0

    def record(rel, number, op, nth, verdict, detail, original, mutated):
        with io.open(results, "a", encoding="utf-8") as f:
            f.write("\t".join([ rel, str(number), op, verdict, detail, str(nth), original.strip(), mutated.strip() ]) + "\n")
        counts[verdict] = counts.get(verdict, 0) + 1

    for index, (rel, number, op, original, mutated) in enumerate(mutants, start=1):

        key              = (rel, str(number), op)
        nth              = occurrences.get(key, 0)
        occurrences[key] = nth + 1

        if key + (str(nth),) in done:
            continue
        if again and key + (str(nth),) not in survivors:
            continue
        if limit and ran >= limit:
            break
        ran += 1

        path = os.path.join(TREE, rel.replace("/", os.sep))
        text, newline, bom = read(path)
        lines = text.replace("\r\n", "\n").split("\n")

        if lines[number - 1] != original:
            record(rel, number, op, nth, "SETUP-ERROR", "the line is not as listed", original, mutated)
            continue

        try:

            lines[number - 1] = mutated + "  /*MUTANT*/"
            write(path, "\n".join(lines), newline, bom)

            before = os.path.getmtime(guard(judge))
            built  = build(judge)

            if built.returncode != 0:
                if COMPILER_ERROR.search((built.stdout or "") + (built.stderr or "")) is None:
                    sys.exit("a build failed without a compiler error: the machine, not the mutant. Stopped at %s:%d.\n%s"
                             % (rel, number, ((built.stdout or "") + (built.stderr or ""))[-3000:]))
                record(rel, number, op, nth, "NOT-VIABLE", "the compiler refuses it", original, mutated)
                continue

            if os.path.getmtime(guard(judge)) <= before:
                record(rel, number, op, nth, "STALE-BINARY", "the PKI the judge loads was not rebuilt", original, mutated)
                continue

            verdict = test(judge, timeout)

            if verdict is TIMEOUT:
                record(rel, number, op, nth, "TIMED-OUT", "the judge still ran after %d s" % timeout, original, mutated)
            elif verdict is None:
                record(rel, number, op, nth, "NO-SUMMARY", "the judge said nothing countable", original, mutated)
            elif verdict[1] != baseline[1]:
                record(rel, number, op, nth, "KILLED", "%d of %d tests ran - the judge broke" % (verdict[1], baseline[1]), original, mutated)
            elif verdict[0] > 0:
                record(rel, number, op, nth, "KILLED", "%d failed: %s" % (verdict[0], ", ".join(verdict[2])), original, mutated)
            else:
                record(rel, number, op, nth, "SURVIVED", "", original, mutated)

        finally:
            write(path, text, newline, bom)

        print("%4d/%d  %s:%d %s   (%s)" % (index, len(mutants), rel.split("/")[-1], number, op,
                                           ", ".join("%s %d" % kv for kv in sorted(counts.items()))), flush=True)

    # The mirror rebuilt as it is, so that the next block's baseline is the PKI's.
    build(judge)

    print("\ndone: " + ", ".join("%s %d" % kv for kv in sorted(counts.items())))


if __name__ == "__main__":
    main()
