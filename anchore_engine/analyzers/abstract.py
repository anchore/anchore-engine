from abc import ABC, abstractmethod
import os
from anchore_engine.analyzers import utils as analyzer_utils


class Analyzer(ABC):
    """
    Base class for analyzers
    """

    analyzer_name = None

    def __init__(self, cmd_args):
        self.config = analyzer_utils.init_analyzer_cmdline(cmd_args, self.analyzer_name)
        self.imgid = self.config.get("imgid")
        self.outputdir = self.config.get("dirs").get("outputdir")
        self.unpackdir = self.config.get("dirs").get("unpackdir")
        assert (
            self.imgid is not None
        ), "Image ID not found in configuration from command-line args: {}".format(
            cmd_args
        )
        assert (
            self.outputdir is not None
        ), "outputdir not found in configuration from command-line args: {}".format(
            cmd_args
        )
        assert (
            self.unpackdir is not None
        ), "unpackdir not found in configuration from command-line args: {}".format(
            cmd_args
        )

    @abstractmethod
    def _run(self):
        """
        Add analyzer specific logic here

        :return: dict of {name:output} pairs for saving in a K/V file
        """

    def run(self):
        output = self._run()
        assert type(output) == dict

        if output:
            for k in output:
                print("Handling output key {}".format(k))
                ofile = os.path.join(self.outputdir, k)
                analyzer_utils.write_kvfile_fromdict(ofile, output[k])
        else:
            print("No analyzer output for {}".format(self.analyzer_name))
            return False

        return output
