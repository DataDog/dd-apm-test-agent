"""Run ``lapdog server`` in the foreground: ``python -m lapdog.self_host [flags]``."""

import argparse
import logging
import os
import sys
from typing import List
from typing import Optional

from aiohttp import web

from ..model_pricing import refresh_price_file
from ..utils import format_bytes
from .app import make_server_app
from .clickhouse import ClickHouseClient
from .clickhouse import ClickHouseError
from .clickhouse import ClickHouseProcess
from .clickhouse import ensure_binary
from .config import add_server_arguments
from .config import config_from_args

log = logging.getLogger("lapdog.self_host")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lapdog server", description="Run the Self-hosted lapdog server in the foreground"
    )
    add_server_arguments(parser)
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    try:
        config = config_from_args(args)
    except ValueError as e:
        print(f"lapdog server: {e}", file=sys.stderr)
        return 2

    try:
        binary = ensure_binary(config.clickhouse_binary)
    except (ClickHouseError, OSError) as e:
        print(f"lapdog server: could not get ClickHouse: {e}", file=sys.stderr)
        return 1

    # Spans are priced once, as they arrive, so get the price list before taking traffic.
    refresh_price_file()

    clickhouse = ClickHouseProcess(
        binary, os.path.join(config.data_dir, "clickhouse"), config.clickhouse_max_memory_bytes
    )
    try:
        clickhouse.start()
    except ClickHouseError as e:
        print(f"lapdog server: {e}", file=sys.stderr)
        return 1

    try:
        client = ClickHouseClient(clickhouse.url, password=clickhouse.password)
        app = make_server_app(config, client, clickhouse)
        log.info(
            "lapdog server listening on http://%s:%d (data in %s, retention %dd, max disk %s)",
            config.host,
            config.port,
            config.data_dir,
            config.retention_days,
            format_bytes(config.max_disk_bytes),
        )
        web.run_app(app, host=config.host, port=config.port, print=None, access_log=None)
    finally:
        clickhouse.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
