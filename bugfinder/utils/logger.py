import logging
import sys

def setup_logger(name="BugFinder", level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)

    # File Handler (optional, can be added later via config)
    
    if not logger.handlers:
        logger.addHandler(ch)

    return logger
