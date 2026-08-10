import logging
import sys


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure root logging for the CLI.

    verbose wins over quiet. In verbose mode also enable DEBUG for the HTTP
    libraries so raw requests/responses are visible.
    """
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
        force=True,
    )

    if verbose:
        logging.getLogger("urllib3").setLevel(logging.DEBUG)
        logging.getLogger("requests").setLevel(logging.DEBUG)
