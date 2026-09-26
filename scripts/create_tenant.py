from __future__ import annotations

import argparse
import asyncio

from app.config.settings import get_settings
from app.models.enums import SecurityLevel, Zone
from app.registry.tenant_registry import TenantRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a ConfidentialKV-Scheduler tenant"
    )

    parser.add_argument(
        "--id",
        required=True,
        dest="tenant_id",
    )

    parser.add_argument(
        "--security-level",
        required=True,
        choices=[level.value for level in SecurityLevel],
    )

    parser.add_argument(
        "--zones",
        required=True,
        nargs="+",
        choices=[zone.value for zone in Zone],
    )

    parser.add_argument(
        "--quota",
        type=int,
        default=1000,
    )

    parser.add_argument(
        "--no-kv-isolation",
        action="store_true",
    )

    return parser


async def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    settings = get_settings()

    registry = TenantRegistry(settings.control_plane_db_path)

    await registry.initialize()

    try:
        tenant, raw_api_key = await registry.create_tenant(
            tenant_id=args.tenant_id,
            security_level=SecurityLevel(args.security_level),
            allowed_zones=[Zone(zone) for zone in args.zones],
            quota_limit=args.quota,
            kv_isolation_required=not args.no_kv_isolation,
        )

        print(f"Created tenant: {tenant.tenant_id}")
        print("API key — save this now; it will not be " "displayed again:")
        print(raw_api_key)

    finally:
        await registry.close()


if __name__ == "__main__":
    asyncio.run(main())
