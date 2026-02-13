import sys
import time
import logging
import dotenv
from usmd_rdsh.self.core import Core

dotenv.load_dotenv()

CORE = Core()

logging.basicConfig(level=logging.INFO)


def main() -> None:
    """Main function."""
    while True:
        if not CORE.is_running():
            CORE.start()
        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        CORE.stop()
        sys.exit(1)
