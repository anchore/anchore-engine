import sys

from anchore_engine import db
from anchore_engine.configuration import localconfig
from anchore_engine.db.entities import upgrade
from anchore_engine.subsys import logger

logger.enable_bootstrap_logging()

if __name__ == "__main__":
    conf = sys.argv[1]
    localconfig.load_config(conf)
    db.initialize(localconfig.get_config())
    logger.info("Running upgrade test...")
    logger.info("Found version: {}".format(upgrade.get_versions()))
    upgrade.run_upgrade()
    logger.info("Found version: {}".format(upgrade.get_versions()))
    logger.info("Upgrade complete")
