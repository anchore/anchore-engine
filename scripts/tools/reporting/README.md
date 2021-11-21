# Unit Test Coverage Priority Tool

We have had a hard time prioritizing how to improve our test coverage at Anchore, and that was a problem I had set out to try and make some progress on using this tool.

This script that can analyze the code and spit out a list of functions that do not have unit tests and sort the list of functions in order of how much they're used across the project.

v1 is completed but it is a little bit of a frankenstein:
     It's not great at determining usages of methods across the application (it's just doing a file keyword search right now) or in the unit test directory.....but it does help a little!

The goal is to use this to make a concerted dent in improving our unit test coverage!


## How to Run

### PyCharm
Create a Python Run Configuration for the script in this directory:

Note: use the full path
Script path: anchore-engine/scripts/tools/reporting/test_coverage_priority.py
Working Directory: anchore-engine/scripts/tools/reporting



## Constraints

Python 3.8
Engine already installed and development environment set up


## Improvement Notes
- Ignore "virtual" functions in an ABC that cannot directly be called.
- If a function doesn't belong to a class, it looks like it will just give you the directory that the function is in rather than the file (e.g. anchore_engine.clients::unpack)
- Determine if ther'es any additional multithreading/processing we can implement that  would help lower the runtime of the script.