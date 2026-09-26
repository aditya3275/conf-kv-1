from __future__ import annotations

import logging
import sys

from app.common.request_context import get_request_id


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


def configure_logging(
    level: int = logging.INFO,
) -> None:
    handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(
        logging.Formatter(
            fmt=(
                "%(asctime)s | "
                "%(levelname)s | "
                "request_id=%(request_id)s | "
                "%(name)s | "
                "%(message)s"
            )
        )
    )

    handler.addFilter(RequestIdFilter())

    root = logging.getLogger()

    root.setLevel(level)

    root.handlers.clear()

    root.addHandler(handler)
