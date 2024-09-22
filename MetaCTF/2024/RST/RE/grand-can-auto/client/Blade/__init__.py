# Load Up a Game Config JSON File or create a Default one if one does not exist
from .config import Config
configs = Config()
configs.load()

# Assets and Resources
from .resource import Resources
resources = Resources()
