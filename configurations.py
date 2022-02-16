import logging

from pathlib import Path


BASEDIR = Path(__file__).parent
INPUT_DATA_FILE = BASEDIR.joinpath('input_data')
INVENTORY_FILE = BASEDIR.joinpath('inventory_file.yaml')
CONNECTIONS = dict()

GIT_ACCESS_TOKEN = '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'
GIT_ACCESS_USERNAME = 'milliardik'

logging.basicConfig()
logging.basicConfig(level=logging.INFO)
logging.getLogger('scrapli').setLevel(logging.CRITICAL)
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)