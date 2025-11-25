import io
import os
import tarfile
import pytest

from wm_server.app.workspaces.docker_utils import stream_single_file_as_tar


def _read_tar_stream(stream):
    """
    Stream-read a tar archive and return a list of (TarInfo, bytes) for members.
    Uses streaming read mode to avoid buffering the entire tar in memory.
    """
    members = []
    with tarfile.open(fileobj=stream, mode="r|*") as tar:
        for m in tar:
            f = tar.extractfile(m)
            body = f.read() if f else b""
            members.append((m, body))
    return members


def test_tar_stream_roundtrip_small():
    content = b"hello world" * 100
    name = "greeting.txt"
    stream = stream_single_file_as_tar(name=name, size=len(content), src=io.BytesIO(content))

    members = _read_tar_stream(stream)
    assert len(members) == 1
    m, body = members[0]
    assert m.name == name
    assert m.size == len(content)
    assert body == content


def test_tar_stream_zero_bytes():
    content = b""
    name = "empty.bin"
    stream = stream_single_file_as_tar(name=name, size=0, src=io.BytesIO(content))

    members = _read_tar_stream(stream)
    assert len(members) == 1
    m, body = members[0]
    assert m.name == name
    assert m.size == 0
    assert body == b""


class NonSeekable(io.BytesIO):
    def __init__(self, initial_bytes: bytes):
        super().__init__(initial_bytes)

    def seekable(self):
        return False

    def seek(self, *args, **kwargs):
        raise io.UnsupportedOperation("seek")


def test_tar_stream_non_seekable_source():
    content = os.urandom(256 * 1024)  # 256 KiB
    name = "random.bin"
    stream = stream_single_file_as_tar(name=name, size=len(content), src=NonSeekable(content))

    members = _read_tar_stream(stream)
    assert len(members) == 1
    m, body = members[0]
    assert m.name == name
    assert m.size == len(content)
    assert body == content


def test_tar_stream_short_source_raises():
    # Size claims 1024 bytes but only 100 bytes are available.
    content = b"x" * 100
    name = "short.bin"
    stream = stream_single_file_as_tar(name=name, size=1024, src=io.BytesIO(content))

    # Reading the tar should fail due to an unexpected end of data.
    with pytest.raises(Exception):
        _ = _read_tar_stream(stream)


def test_tar_stream_small_chunk_backpressure():
    # Ensure consumer reading small chunks still drains queue without deadlock and preserves data
    data = os.urandom(1 * 1024 * 1024)  # 1 MiB
    name = "small_chunk.bin"
    stream = stream_single_file_as_tar(name=name, size=len(data), src=io.BytesIO(data))

    # Read the tar stream in very small chunks to simulate backpressure
    buf = bytearray()
    with tarfile.open(fileobj=stream, mode="r|*") as tar:
        for m in tar:
            f = tar.extractfile(m)
            assert f is not None
            while True:
                chunk = f.read(1024)  # 1 KiB
                if not chunk:
                    break
                buf += chunk
    assert bytes(buf) == data


def test_tar_stream_min_queue_size():
    # Queue size of 1 to maximize producer/consumer synchronization
    payload = b"a" * (128 * 1024)  # 128 KiB
    stream = stream_single_file_as_tar(name="q1.bin", size=len(payload), src=io.BytesIO(payload), queue_size=1)
    members = _read_tar_stream(stream)
    assert len(members) == 1
    m, body = members[0]
    assert m.name == "q1.bin"
    assert m.size == len(payload)
    assert body == payload


def test_tar_stream_concurrent_instances():
    # Run multiple streamers in parallel and verify each returns correct content
    contents = [os.urandom(256 * 1024), os.urandom(300 * 1024), os.urandom(512 * 1024)]
    names = ["c1.bin", "c2.bin", "c3.bin"]
    streams = [stream_single_file_as_tar(name=n, size=len(c), src=io.BytesIO(c)) for n, c in zip(names, contents)]

    results = [None] * len(streams)

    def _worker(idx: int) -> None:
        results[idx] = _read_tar_stream(streams[idx])

    import threading
    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(len(streams))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for idx, (m_list, expected_name, expected_body) in enumerate(zip(results, names, contents)):
        assert len(m_list) == 1, f"stream {idx} returned wrong number of members"
        m, body = m_list[0]
        assert m.name == expected_name
        assert m.size == len(expected_body)
        assert body == expected_body