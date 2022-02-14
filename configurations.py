import logging

from pathlib import Path


BASEDIR = Path(__file__).parent
INPUT_DATA_FILE = BASEDIR.joinpath('input_data')
INVENTORY_FILE = BASEDIR.joinpath('inventory_file.yaml')
CONNECTIONS = dict()


logging.basicConfig()
logging.basicConfig(level=logging.INFO)
logging.getLogger('scrapli').setLevel(logging.CRITICAL)
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)