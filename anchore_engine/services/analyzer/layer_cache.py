import operator
import os

from anchore_engine.configuration.localconfig import get_config
from anchore_engine.subsys import logger


def handle_layer_cache():
    """
    Do layer cache cleanup

    :return:
    """

    localconfig = get_config()
    myconfig = localconfig["services"]["analyzer"]

    cachemax_gbs = int(myconfig.get("layer_cache_max_gigabytes", 1))
    cachemax = cachemax_gbs * 1000000000

    try:
        tmpdir = localconfig["tmp_dir"]
    except Exception as err:
        logger.warn("could not get tmp_dir from localconfig - exception: " + str(err))
        tmpdir = "/tmp"
    use_cache_dir = os.path.join(tmpdir, "anchore_layercache")
    if os.path.exists(use_cache_dir):
        totalsize = 0
        layertimes = {}
        layersizes = {}

        for f in os.listdir(os.path.join(use_cache_dir, "sha256")):
            layerfile = os.path.join(use_cache_dir, "sha256", f)
            layerstat = os.stat(layerfile)
            totalsize = totalsize + layerstat.st_size
            layersizes[layerfile] = layerstat.st_size
            layertimes[layerfile] = max(
                [layerstat.st_mtime, layerstat.st_ctime, layerstat.st_atime]
            )

        if totalsize > cachemax:
            logger.debug(
                "layer cache total size ("
                + str(totalsize)
                + ") exceeds configured cache max ("
                + str(cachemax)
                + ") - performing cleanup"
            )
            currsize = totalsize
            sorted_layers = sorted(list(layertimes.items()), key=operator.itemgetter(1))
            while currsize > cachemax:
                rmlayer = sorted_layers.pop(0)
                logger.debug("removing cached layer: " + str(rmlayer))
                os.remove(rmlayer[0])
                currsize = currsize - layersizes[rmlayer[0]]
                logger.debug("currsize after remove: " + str(currsize))

    return True
