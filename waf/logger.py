import json
import logging
import os
from logging.handlers import RotatingFileHandler
from threading import Lock
from datetime import datetime, timezone


class JsonAuditLogger:

    def __init__(
        self,
        path: str,
        max_bytes: int,
        backups: int
    ):

        directory = os.path.dirname(path)

        if directory:
            os.makedirs(
                directory,
                exist_ok=True
            )

        self.path = path
        self._lock = Lock()

        self._logger = logging.getLogger(
            "sentinelshield.audit"
        )

        self._logger.setLevel(
            logging.INFO
        )

        self._logger.propagate = False

        if not self._logger.handlers:

            handler = RotatingFileHandler(
                path,
                maxBytes=max_bytes,
                backupCount=backups,
                encoding="utf-8"
            )

            handler.setFormatter(
                logging.Formatter(
                    "%(message)s"
                )
            )

            self._logger.addHandler(
                handler
            )

    def log(self, event: dict):

        event = dict(event)

        event.setdefault(
            "timestamp",
            datetime.now(
                timezone.utc
            ).isoformat()
        )

        line = json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":")
        )

        with self._lock:
            self._logger.info(line)

    def read_recent(
        self,
        limit: int = 200
    ) -> list[dict]:

        if not os.path.exists(
            self.path
        ):
            return []

        with self._lock:

            with open(
                self.path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:

                lines = file.readlines()[
                    -limit:
                ]

        result = []

        for line in reversed(lines):

            try:
                result.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:
                continue

        return result
