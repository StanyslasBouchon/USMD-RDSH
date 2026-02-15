import sys
import logging
from typing import Optional
import dotenv

dotenv.load_dotenv()
logging.basicConfig(level=logging.DEBUG)

from usmd_rdsh.self.core import Core  # pylint: disable=wrong-import-position


CORE: Optional[Core] = None


def main() -> None:
    """Main function."""
    CORE.run()


if __name__ == "__main__":
    CORE = Core()

    try:
        main()
    except KeyboardInterrupt:
        CORE.stop()
        sys.exit(1)
