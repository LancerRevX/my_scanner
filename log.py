import sys
from functools import partial
import logging

# legacy_logger.getLogger("charset_normalizer").setLevel(legacy_logger.ERROR)
# logging.remove()

# Setup additional logging levels, from the less important to the more critical
# Each attempted mutated request will be logged as VERBOSE as it generates a lot of output
# Each attacked original request will be logged as INFO
# Others info like currently used attack module must be logged even in quiet mode so BLUE level must be used as least

# # logging.debug is level 10, this is the value defined in Python's logging module and is reused by loguru
# logging.level("VERBOSE", no=15)
# # logging.info is 20
# logging.level("BLUE", no=21, color="<blue>")
# logging.level("GREEN", no=22, color="<green>")
# # logging.success is 25
# # logging.warning is 30
# logging.level("ORANGE", no=35, color="<yellow>")
# # logging.error is 40
# logging.level("RED", no=45, color="<red>")
# # logging.critical is 50

log_blue = lambda *args: None
log_green = lambda *args: None
log_red = lambda *args: None
log_orange = lambda *args: None
log_verbose = lambda *args: None

# Set default logging
# logging.add(sys.stdout, colorize=False, format="{message}", level="INFO")
