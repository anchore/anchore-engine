import re

import collections

import json

import operator

import os

import threading

import inspect
import pkgutil
import importlib

ROOTDIR = "../../../anchore_engine"
UNIT_TEST_DIR = "../../../tests/unit/anchore_engine"
TEMPDIR = "/tmp/engine-test-coverage"

# Skip constructors, not necessarily good criteria for test coverage reporting
SKIP_FUNCS = ["__init__"]

SearchKeyword = collections.namedtuple("SearchKeyword", ["imports", "keywords"])


def list_functions(mod):
    pure_functions = [
        func.__name__
        for func in mod.__dict__.values()
        if (inspect.isfunction(func) or inspect.ismethod(func))
        and inspect.getmodule(func) == mod
        and func.__name__ not in SKIP_FUNCS
    ]

    classes = [
        clas
        for clas in mod.__dict__.values()
        if inspect.isclass(clas) and inspect.getmodule(clas) == mod
    ]
    # print(str(len(classes)) + " classes found in module: " + mod.__name__)

    class_functions = list()
    for clas in classes:
        class_functions.extend(list_class_functions(clas, mod))

    total_functions = pure_functions
    if len(class_functions) > 0:
        total_functions.extend(class_functions)

    return total_functions


def list_class_functions(clas, mod):
    functions = []
    # print("resolving " + clas.__name__ + " functions")
    class_functions = [
        clas.__name__ + "." + name
        for name, func in inspect.getmembers(clas, inspect.isfunction)
        if inspect.getmodule(func) == mod and func.__name__ not in SKIP_FUNCS
    ]
    functions.extend(class_functions)

    class_methods = [
        clas.__name__ + "." + name
        for name, method in inspect.getmembers(clas, inspect.ismethod)
        if inspect.getmodule(method) == mod and method.__name__ not in SKIP_FUNCS
    ]
    functions.extend(class_methods)

    # TODO: figure out how to resolve sub class method searching
    # subclasses = inspect.getmembers(clas, inspect.isclass)
    # print(len(subclasses))
    # if len(subclasses) > 0:
    #     for subclass in subclasses:
    #         functions.extend(list_class_functions(functions, subclass, mod))

    return functions


def get_modules(pkg, dir):
    return [
        {"pkg": pkg, "dir": dir, "name": name, "ispkg": ispkg}
        for _, name, ispkg in pkgutil.iter_modules([dir])
    ]


def resolve_all_engine_packages():
    toplevel_modules = get_modules("anchore_engine", ROOTDIR)

    modules = list()
    methods = list()
    for module in toplevel_modules:
        if module.get("ispkg"):
            modules.append(module)
        else:
            functions = get_module_functions(module)
            methods.append(
                {
                    "pkg": module.get("pkg"),
                    "dir": module.get("dir"),
                    "name": module.get("name"),
                    "functions": functions,
                }
            )

    resolver_threads = []
    for module in modules:
        resolver = ModuleFunctionResolver(module)
        resolver.start()
        resolver_threads.append(resolver)

    for resolver_thread in resolver_threads:
        resolver_thread.join()

    with open("{}/{}.txt".format(TEMPDIR, "anchore_engine_rootpkg"), "w") as f:
        for method in methods:
            for function in method["functions"]:
                method_fullname = "{}.{}::{}\n".format(
                    method["pkg"], method["name"], function
                )
                f.write(method_fullname)


def get_module_functions(module_dict):
    module_fullname = module_dict.get("pkg") + "." + module_dict.get("name")
    module = importlib.import_module(module_fullname)

    # list of tuples ('methodname', function)
    return list_functions(module)


def is_mod_function(mod, func):
    return inspect.isfunction(func) and inspect.getmodule(func) == mod


def resolve_module_functions(modules):
    functions = []
    for module in modules:
        try:
            if module.get("ispkg"):
                pkg = module.get("pkg") + "." + module.get("name")
                dir = module.get("dir") + "/" + module.get("name")
                package_modules = get_modules(pkg, dir)
                functions.extend(resolve_module_functions(package_modules))
            else:
                module_functions = get_module_functions(module)
                functions.extend(module_functions)
        except Exception as err:
            # Hide API controller errors, we don't need to catalog them anyways because they're not valid for this report
            if isinstance(err, AttributeError) and str(err).startswith(
                "'NoneType' object has no attribute"
            ):
                pass
            else:
                print("failed to resolve module: {} with error {}".format(module, err))

    return functions


class ModuleFunctionResolver(threading.Thread):
    def __init__(self, module):
        threading.Thread.__init__(self)
        self.module = module

    def run(self):
        functions = resolve_module_functions([self.module])

        if not os.path.exists(TEMPDIR):
            os.mkdir(TEMPDIR)

        with open("{}/{}.txt".format(TEMPDIR, self.module.get("name")), "w") as f:
            for function in functions:
                f.write(
                    "{}.{}::{}\n".format(
                        self.module["pkg"], self.module["name"], function
                    )
                )


class ModuleFunctionUsageResolver(threading.Thread):
    def __init__(self, rootlevel_pkg_file):
        threading.Thread.__init__(self)
        self.pkg_file = rootlevel_pkg_file

    def run(self):
        # This will come up with a list of methods to search
        method_fullnames = []
        with open(self.pkg_file) as file:
            for line in file:
                method_fullnames.append(line)

        methods_and_usages = {}
        for method in method_fullnames:
            keywords = self.get_method_keywords(method)
            usages = self.keyword_search(keywords)
            methods_and_usages[method.strip()] = usages

        sorted_usages = dict(
            sorted(methods_and_usages.items(), key=operator.itemgetter(1), reverse=True)
        )
        usage_filename = os.path.basename(self.pkg_file).split(".")[0]

        if not os.path.exists("{}/usage".format(TEMPDIR)):
            os.mkdir("{}/usage".format(TEMPDIR))

        with open("{}/usage/{}.json".format(TEMPDIR, usage_filename), "w") as f:
            json.dump(sorted_usages, f)

    ## TODO: we need to either refine this process so we can get more accurate results or think of a different appraoch
    ## the keywords generated here may cause duplicate usages to be reported across what are actually different classes/pkgs/methods
    @staticmethod
    def get_method_keywords(method):
        # full_method format: anchore_engine.package::Class.method
        method_parts = method.strip().split("::")
        pkg = method_parts[0].replace(".", "\.")
        class_and_method = method_parts[1]

        import_pattern = re.compile("import.*{}.*".format(pkg))
        imports = [import_pattern]

        # Possible formats: Class.method, method
        class_and_method_parts = class_and_method.split(".")
        classname = class_and_method_parts[0]
        class_import_pattern = re.compile("from {}.*import.*{}".format(pkg, classname))
        imports.append(class_import_pattern)
        keywords = [class_and_method]
        if len(class_and_method_parts) > 1:
            keywords.append(class_and_method_parts[1])

        return SearchKeyword(imports, keywords)

    @staticmethod
    def keyword_search(search):
        keyword_finds = 0
        file_count = 0
        for root, dirs, files in os.walk(ROOTDIR):  # walk the root dir
            for filename in files:  # iterate over the files in the current dir
                file_path = os.path.join(root, filename)  # build the file path

                if not file_path.endswith(".py"):
                    continue

                file_count += 1
                try:
                    with open(file_path, "rb") as f:  # open the file for reading
                        # read the file line by line, looking for an import
                        # import_found = False
                        # # TODO: this isn't working because the modules returned in 1st step don't have the filenames they're imported from
                        # for line in f:  # use: for i, line in enumerate(f) if you need line numbers
                        #     try:
                        #         line = line.decode("utf-8")  # try to decode the contents to utf-8
                        #     except ValueError:  # decoding failed, skip the line
                        #         print("failed to decode file: {}".format(file_path))
                        #         continue
                        #
                        #     for import_regex in search.imports:
                        #         if re.match(import_regex, line):
                        #             import_found = True
                        #             break
                        #
                        # # if we find an import, look for keywords
                        # if import_found:
                        for line in f:
                            try:
                                line = line.decode(
                                    "utf-8"
                                )  # try to decode the contents to utf-8
                            except ValueError:  # decoding failed, skip the line
                                print("failed to decode file: {}".format(file_path))
                                continue
                            for keyword in search.keywords:
                                if (
                                    keyword in line
                                ):  # if the keyword exists on the current line...
                                    keyword_finds += 1
                except (IOError, OSError):  # ignore read and permission errors
                    print("error reading file: {}".format(file_path))
                    pass
        return keyword_finds


class ModuleFunctionTestedResolver(threading.Thread):
    def __init__(self, rootlevel_pkg_file):
        threading.Thread.__init__(self)
        self.pkg_file = rootlevel_pkg_file

    def run(self):
        # This will come up with a list of methods to search
        method_fullnames = []
        with open(self.pkg_file) as json_file:
            usage_data = json.load(json_file)
            for key, _ in usage_data.items():
                method_fullnames.append(key)

        tested_methods = []
        for method in method_fullnames:
            keywords = self.get_method_keywords(method)
            found = self.keyword_search(keywords)
            if found:
                tested_methods.append(method.strip())

        usage_filename = os.path.basename(self.pkg_file).split(".")[0]

        if not os.path.exists("{}/tested".format(TEMPDIR)):
            os.mkdir("{}/tested".format(TEMPDIR))

        with open("{}/tested/{}.json".format(TEMPDIR, usage_filename), "w") as f:
            json.dump(tested_methods, f)

    ## TODO: we need to either refine this process so we can get more accurate results or think of a different appraoch
    ## the keywords generated here may cause duplicate usages to be reported across what are actually different classes/pkgs/methods
    @staticmethod
    def get_method_keywords(method):
        # full_method format: anchore_engine.package::Class.method
        method_parts = method.strip().split("::")
        pkg = method_parts[0].replace(".", "\.")
        class_and_method = method_parts[1]

        import_pattern = re.compile("import.*{}.*".format(pkg))
        imports = [import_pattern]

        # Possible formats: Class.method, method
        class_and_method_parts = class_and_method.split(".")
        classname = class_and_method_parts[0]
        class_import_pattern = re.compile("from {}.*import.*{}".format(pkg, classname))
        imports.append(class_import_pattern)
        keywords = [class_and_method]
        if len(class_and_method_parts) > 1:
            keywords.append(class_and_method_parts[1])

        return SearchKeyword(imports, keywords)

    @staticmethod
    def keyword_search(search):
        file_count = 0
        for root, dirs, files in os.walk(UNIT_TEST_DIR):  # walk the root dir
            for filename in files:  # iterate over the files in the current dir
                file_path = os.path.join(root, filename)  # build the file path

                if not file_path.endswith(".py"):
                    continue

                file_count += 1
                try:
                    with open(file_path, "rb") as f:  # open the file for reading
                        # read the file line by line, looking for an import
                        # import_found = False
                        # # TODO: this isn't working because the modules returned in 1st step don't have the filenames they're imported from
                        # for line in f:  # use: for i, line in enumerate(f) if you need line numbers
                        #     try:
                        #         line = line.decode("utf-8")  # try to decode the contents to utf-8
                        #     except ValueError:  # decoding failed, skip the line
                        #         print("failed to decode file: {}".format(file_path))
                        #         continue
                        #
                        #     for import_regex in search.imports:
                        #         if re.match(import_regex, line):
                        #             import_found = True
                        #             break
                        #
                        # # if we find an import, look for keywords
                        # if import_found:
                        for line in f:
                            try:
                                line = line.decode(
                                    "utf-8"
                                )  # try to decode the contents to utf-8
                            except ValueError:  # decoding failed, skip the line
                                print("failed to decode file: {}".format(file_path))
                                continue
                            for keyword in search.keywords:
                                if (
                                    keyword in line
                                ):  # if the keyword exists on the current line...
                                    return True
                except (IOError, OSError):  # ignore read and permission errors
                    print("error reading file: {}".format(file_path))
                    pass
        return False


# This method will determine all methods in the application, under the anchore_engine directory
# and list them in files per root-level package in /tmp/engine-test-coverage
print("generating list of all application methods")
resolve_all_engine_packages()

# Next, we want to look for usages of each of those methods throughout the project
print("determining usages across the application")
usage_threads = []
for root, dirs, files in os.walk(TEMPDIR):
    for filename in files:
        if not filename.endswith("txt"):
            continue
        file_path = os.path.join(root, filename)
        usage_resolver = ModuleFunctionUsageResolver(file_path)
        usage_resolver.start()
        usage_threads.append(usage_resolver)

for thread in usage_threads:
    thread.join()

print("now searching for methods in the unit test directory")

# Next step is to find references of each of the methods in the ./tests/unit/anchore_engine directory
# This will tell us which methods to remove from the master list
tested_threads = []
for root, dirs, files in os.walk("{}/usage".format(TEMPDIR)):
    for filename in files:
        usage_filepath = os.path.join(root, filename)
        tested_resolver = ModuleFunctionTestedResolver(usage_filepath)
        tested_resolver.start()
        tested_threads.append(tested_resolver)

for thread in tested_threads:
    thread.join()

print("loading usage data into memory")
# Now we can load up each of the JSON files into some data structures to parse
usage_data = {}
for root, dirs, files in os.walk("{}/usage".format(TEMPDIR)):
    print("{} usage files found".format(str(len(files))))
    for filename in files:
        file_path = os.path.join(root, filename)
        with open(file_path) as json_file:
            data = json.load(json_file)
            usage_data = {**usage_data, **data}

print("{} usage methods found".format(str(len(usage_data.keys()))))
print("loading tested methods data into memory")
tested_methods = []
for root, dirs, files in os.walk("{}/tested".format(TEMPDIR)):
    print("{} tested methods data files found".format(str(len(files))))
    for filename in files:
        file_path = os.path.join(root, filename)
        with open(file_path) as json_file:
            data = json.load(json_file)
            tested_methods.extend(data)

print("{} tested methods found".format(str(len(tested_methods))))

print("removing tested methods from the usage report")
# And remove the tested methods from the usage methods
for tested_method in tested_methods:
    usage_data.pop(tested_method, None)


# The resulting list, sorted by # of usages, should be methods that have no reference in the tests directory
# This should be able to tell us how to prioritize the test coverage improvement effort in anchore-engine
print("sorting usage data one last time")
sorted_usage_data = dict(
    sorted(usage_data.items(), key=operator.itemgetter(1), reverse=True)
)
print("{} methods found".format(str(len(sorted_usage_data))))
for key, value in sorted_usage_data.items():
    print(
        "Method {} is untested and used {} times throughout the project".format(
            key, value
        )
    )

exit(0)
print("removing methods which have tests from list")
