from __future__ import annotations

import argparse
import asyncio

from app.config.settings import get_settings
from app.models.backend import Backend
from app.models.enums import BackendStatus, Zone
from app.registry.backend_registry import BackendRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Register a ConfidentialKV serving backend"
    )

    parser.add_argument(
        "--id",
        required=True,
        dest="backend_id",
    )

    parser.add_argument(
        "--endpoint",
        required=False,
        default=None,
    )

    parser.add_argument(
        "--zone",
        required=True,
        choices=[zone.value for zone in Zone],
    )

    parser.add_argument(
        "--gpu",
        type=int,
        nargs="*",
        default=[],
    )

    parser.add_argument(
        "--available",
        action="store_true",
    )

    return parser


async def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    settings = get_settings()

    registry = BackendRegistry(settings.control_plane_db_path)

    await registry.initialize()

    try:
        backend = Backend(
            backend_id=args.backend_id,
            endpoint=args.endpoint,
            zone=Zone(args.zone),
            gpu_ids=args.gpu,
            configured_status=(
                BackendStatus.AVAILABLE if args.available else BackendStatus.UNAVAILABLE
            ),
            capacity_available=args.available,
        )

        await registry.register_backend(backend)

        print(f"Registered backend: {backend.backend_id}")

    finally:
        await registry.close()


if __name__ == "__main__":
    asyncio.run(main())
