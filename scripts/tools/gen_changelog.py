#!/usr/bin/python3
import re
import subprocess
import sys

if len(sys.argv) != 2:
    print("Must have source tag to compare to")
    exit(1)

start = sys.argv[1]

exclusions = ["ci:", "test:", "tests:", "[WIP]", "chore:", "[test]", "[chore]"]

line_re = re.compile(r"([a-f0-9]{8}) (\S+)")

output = subprocess.check_output(
    ["git", "log", start + "..HEAD", "--oneline", "--no-merges"]
)
changes = []
questionable = []
for line in output.splitlines():
    line = str(line, "utf-8")
    m = line_re.match(line)

    if not m:
        questionable.append(line)

    if m.group(2) in exclusions:
        continue

    changes.append(line)


print("Investigate: \n{}".format("\n".join(questionable)))
print("Changelog: \n{}".format("\n".join(changes)))
print("Complete!")
