from loader.initial_loader import InitialLoader
from config.settings import INITIAL_LOAD_LIMIT

if __name__ == "__main__":

    loader = InitialLoader()

    loader.run(limit=INITIAL_LOAD_LIMIT)