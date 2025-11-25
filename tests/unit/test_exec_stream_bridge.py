import asyncio
from wm_server.app.workspaces.docker_utils import aiter_from_sync_iter


async def _collect(ait):
    buf = bytearray()
    async for chunk in ait:
        buf += chunk
    return bytes(buf)


def test_aiter_from_sync_iter_basic():
    chunks = [b"a", b"bc", b"", b"def"]
    data = asyncio.run(_collect(aiter_from_sync_iter(chunks)))
    assert data == b"abcdef"


def test_aiter_from_sync_iter_empty():
    chunks = []
    data = asyncio.run(_collect(aiter_from_sync_iter(chunks)))
    assert data == b""