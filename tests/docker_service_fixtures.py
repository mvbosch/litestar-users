from __future__ import annotations

import asyncio
import os
import re
import subprocess
import sys
import timeit
from collections.abc import Awaitable, Generator
from typing import Any, Callable

import asyncpg
import pytest


async def wait_until_responsive(
    check: Callable[..., Awaitable],
    timeout: float,
    pause: float,
    **kwargs: Any,
) -> None:
    """Wait until a service is responsive.

    Args:
        check: Coroutine, return truthy value when waiting should stop.
        timeout: Maximum seconds to wait.
        pause: Seconds to wait between calls to `check`.
        **kwargs: Given as kwargs to `check`.
    """
    ref = timeit.default_timer()
    now = ref
    while (now - ref) < timeout:  # sourcery skip
        if await check(**kwargs):
            return
        await asyncio.sleep(pause)
        now = timeit.default_timer()

    raise RuntimeError("Timeout reached while waiting on service!")


class DockerServiceRegistry:
    def __init__(self) -> None:
        self._running_services: set[str] = set()
        self.docker_ip = self._get_docker_ip()
        self._base_command = [
            "docker",
            "compose",
            "--file=tests/docker-compose.yml",
            "--project-name=litestar_users_pytest",
        ]

    def _get_docker_ip(self) -> str:
        docker_host = os.environ.get("DOCKER_HOST", "").strip()
        if not docker_host or docker_host.startswith("unix://"):
            return "127.0.0.1"

        if match := re.match(r"^tcp://(.+?):\d+$", docker_host):
            return match[1]

        raise ValueError(f'Invalid value for DOCKER_HOST: "{docker_host}".')

    def run_command(self, *args: str) -> None:
        subprocess.run([*self._base_command, *args], check=True, capture_output=True)

    async def start(
        self,
        name: str,
        *,
        check: Callable[..., Awaitable],
        timeout: float = 30,
        pause: float = 0.1,
        **kwargs: Any,
    ) -> None:
        if name not in self._running_services:
            self.run_command("up", "-d", name)
            self._running_services.add(name)

            await wait_until_responsive(
                check=check,
                timeout=timeout,
                pause=pause,
                host=self.docker_ip,
                **kwargs,
            )

    def stop(self, name: str) -> None:
        pass

    def down(self) -> None:
        self.run_command("down", "-t", "5")


@pytest.fixture(scope="session")
def docker_services() -> Generator[DockerServiceRegistry, None, None]:
    if sys.platform not in ("linux", "darwin") or os.environ.get("SKIP_DOCKER_TESTS"):
        pytest.skip("Docker not available on this platform")

    registry = DockerServiceRegistry()
    try:
        yield registry
    finally:
        registry.down()


@pytest.fixture(scope="session")
def docker_ip(docker_services: DockerServiceRegistry) -> str:
    return docker_services.docker_ip


async def postgres_responsive(host: str) -> bool:
    try:
        conn = await asyncpg.connect(
            host=host, port=5423, user="postgres", database="postgres", password="super-secret"
        )
    except (ConnectionError, asyncpg.CannotConnectNowError):
        return False

    try:
        return (await conn.fetchrow("SELECT 1"))[0] == 1  # type: ignore[no-any-return]
    finally:
        await conn.close()


@pytest.fixture()
async def postgres_service(docker_services: DockerServiceRegistry) -> None:
    await docker_services.start("postgres", check=postgres_responsive)
