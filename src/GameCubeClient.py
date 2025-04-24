from abc import ABC, abstractmethod
import asyncio
from enum import IntEnum, IntFlag
import itertools
from logging import Logger
import struct
from typing import NamedTuple
import dolphin_memory_engine  # type: ignore
import subprocess
import Utils

GC_GAME_ID_ADDRESS = 0x80000000


class GameCubeException(Exception):
    pass


class DolphinException(GameCubeException):
    pass


class NintendontException(GameCubeException):
    pass


class GameCubeClient(ABC):
    @abstractmethod
    def is_connected(self) -> bool:
        ...

    @abstractmethod
    async def connect(self):
        ...

    @abstractmethod
    def disconnect(self):
        ...

    @abstractmethod
    async def read_pointer(self, pointer: int, offset: int, byte_count: int) -> bytes | None:
        ...

    @abstractmethod
    async def read_address(self, address: int, bytes_to_read: int) -> bytes:
        ...

    @abstractmethod
    async def write_pointer(self, pointer: int, offset: int, data: bytes):
        ...

    @abstractmethod
    async def write_address(self, address: int, data: bytes):
        ...


class DolphinClient(GameCubeClient):
    dolphin: dolphin_memory_engine  # type: ignore
    logger: Logger

    def __init__(self, logger: Logger):
        self.dolphin = dolphin_memory_engine
        self.logger = logger

    def is_connected(self):
        try:
            self.__assert_connected()
            return True
        except Exception:
            return False

    async def connect(self):
        if not self.dolphin.is_hooked():
            self.dolphin.hook()
        if not self.dolphin.is_hooked():
            raise DolphinException(
                "Could not connect to Dolphin, verify that you have a game running in the emulator"
            )

    def disconnect(self):
        if self.dolphin.is_hooked():
            self.dolphin.un_hook()

    def __assert_connected(self):
        """Custom assert function that returns a DolphinException instead of a generic RuntimeError if the connection is lost"""
        try:
            self.dolphin.assert_hooked()
            # For some reason the dolphin_memory_engine.is_hooked() function doesn't recognize when the game is closed, checking if memory is available will assert the connection is alive
            self.dolphin.read_bytes(GC_GAME_ID_ADDRESS, 1)
        except RuntimeError as e:
            self.disconnect()
            raise DolphinException(e)

    def verify_target_address(self, target_address: int, read_size: int):
        """Ensures that the target address is within the valid range for GC memory"""
        if target_address < 0x80000000 or target_address + read_size > 0x81800000:
            raise DolphinException(f"{target_address:x} -> {target_address + read_size:x} is not a valid for GC memory")

    async def read_pointer(self, pointer: int, offset: int, byte_count: int):
        self.__assert_connected()

        address = None
        try:
            address = self.dolphin.follow_pointers(pointer, [0])
        except RuntimeError:
            return None

        if not self.dolphin.is_hooked():
            raise DolphinException("Dolphin no longer connected")

        address += offset
        return await self.read_address(address, byte_count)

    async def read_address(self, address: int, bytes_to_read: int):
        self.__assert_connected()
        self.verify_target_address(address, bytes_to_read)
        result = self.dolphin.read_bytes(address, bytes_to_read)
        return result

    async def write_pointer(self, pointer: int, offset: int, data: bytes):
        self.__assert_connected()
        address = None
        try:
            address = self.dolphin.follow_pointers(pointer, [0])
        except RuntimeError:
            return None

        if not self.dolphin.is_hooked():
            raise DolphinException("Dolphin no longer connected")

        address += offset
        return await self.write_address(address, data)

    async def write_address(self, address: int, data: bytes):
        self.__assert_connected()
        result = self.dolphin.write_bytes(address, data)
        return result


def assert_no_running_dolphin() -> bool:
    """Only checks on windows for now, verifies no existing instances of dolphin are running."""
    if Utils.is_windows:
        if get_num_dolphin_instances() > 0:
            return False
    return True


def get_num_dolphin_instances() -> int:
    """Only checks on windows for now, kind of brittle so if it causes problems then just ignore it"""
    try:
        if Utils.is_windows:
            output = subprocess.check_output("tasklist", shell=True).decode()
            lines = output.strip().split("\n")
            count = sum("Dolphin.exe" in line for line in lines)
            return count
        return 0
    except BaseException:
        return 0


NINTENDONT_PORT = 43673


class NintendontMemoryOperationType(IntEnum):
    READ_COMMANDS = 0
    REQUEST_VERSION = 1


class NintendontOperationHeader(IntFlag):
    HAS_READ = 0x80
    HAS_WRITE = 0x40
    IS_WORD = 0x20
    HAS_OFFSET = 0x10
    ADDRESS_INDEX_MASK = 0xF

    @classmethod
    def make(cls, read: bool, write: bool, is_word: bool, indirect: bool, address_index: int):
        if address_index > cls.ADDRESS_INDEX_MASK:
            raise ValueError(f"Address index too large: Max {cls.ADDRESS_INDEX_MASK}, got {address_index}")
        if address_index < 0:
            raise ValueError(f"Address must be nonnegative, got {address_index}")
        self = cls(address_index)
        if read:
            self |= cls.HAS_READ
        if write:
            self |= cls.HAS_WRITE
        if is_word:
            self |= cls.IS_WORD
        if indirect:
            self |= cls.HAS_OFFSET
        return self


# No support for words
class NintendontOperation(NamedTuple):
    header: NintendontOperationHeader
    size: int
    indirect_offset: int | None
    data: bytes | None

    @classmethod
    def make_read(cls, address_index: int, size: int, indirect_offset: int | None = None):
        header = NintendontOperationHeader.make(True, False, False, indirect_offset is not None, address_index)
        return cls(header, size, indirect_offset, None)

    @classmethod
    def make_write(cls, read: bool, address_index: int, data: bytes, indirect_offset: int | None = None):
        header = NintendontOperationHeader.make(read, True, False, indirect_offset is not None, address_index)
        return cls(header, len(data), indirect_offset, data)

    def is_read(self) -> bool:
        return NintendontOperationHeader.HAS_READ in self.header

    def to_bytes(self) -> bytes:
        if self.indirect_offset is None:
            data = struct.pack(">BB", self.header, self.size)
        else:
            data = struct.pack(">BBH", self.header, self.size, self.indirect_offset)
        if self.data is None:
            return data
        else:
            return data + self.data

class NintendontMetaInfo(NamedTuple):
    protocol_version: int
    max_input_bytes: int
    max_output_bytes: int
    max_addresses: int


class NintendontClient(GameCubeClient):
    address: str | None
    streams: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None
    meta_info: NintendontMetaInfo | None
    lock: asyncio.Lock
    logger: Logger

    def __init__(self, logger: Logger):
        self.address = None
        self.streams = None
        self.meta_info = None
        self.lock = asyncio.Lock()
        self.logger = logger

    def is_connected(self):
        return self.streams is not None

    def set_address(self, new_address: str | None):
        if new_address != self.address and self.is_connected():
            self.logger.info("Nintendont address changed, disconnecting.")
            self.disconnect()
        self.address = new_address

    async def connect(self):
        if self.address is None:
            raise NintendontException("Address is not set")

        try:
            self.streams = await asyncio.open_connection(self.address, NINTENDONT_PORT)
        except OSError as e:
            raise NintendontException from e

        try:
            data = struct.pack(">BBBB", NintendontMemoryOperationType.REQUEST_VERSION, 0, 0, True)
            result = await self.__make_request(data)
            self.meta_info = NintendontMetaInfo._make(struct.unpack(">IIII", result))
            self.logger.debug(f"Protocol version: {self.meta_info.protocol_version}")
            self.logger.debug(f"Max input bytes: {self.meta_info.max_input_bytes}")
            self.logger.debug(f"Max output bytes: {self.meta_info.max_output_bytes}")
            self.logger.debug(f"Max addresses: {self.meta_info.max_addresses}")
        except:
            self.disconnect()
            raise

    def disconnect(self):
        if self.streams is not None:
            self.streams[1].close()
            self.streams = self.meta_info = None

    async def __make_request(self, data: bytes | bytearray) -> bytes:
        async with self.lock:
            if self.streams is None:
                raise NintendontException("Not connected to Nintendont")
            reader, writer = self.streams

            try:
                writer.write(data)
                await asyncio.wait_for(writer.drain(), timeout=5)
                response = await asyncio.wait_for(reader.read(1024), timeout=5)

                if response == b"":
                    self.disconnect()
                    raise NintendontException("Connection closed")

                return response
            except asyncio.TimeoutError as e:
                self.disconnect()
                raise NintendontException("Connection timed out") from e
            except ConnectionResetError as e:
                self.disconnect()
                raise NintendontException("Connection reset") from e

    async def __request_operations(self, addresses: list[int], memory_operations: list[NintendontOperation]) -> list[bytes | None]:
        if self.meta_info is None:
            raise NintendontException("Not connected to Nintendont")

        if len(addresses) > self.meta_info.max_addresses:
            raise NintendontException(f"Too many addresses: Max is {self.meta_info.max_addresses}, got {len(addresses)}")

        data = bytearray()
        data.extend(struct.pack(">BBBB", NintendontMemoryOperationType.READ_COMMANDS, len(memory_operations), len(addresses), True))
        data.extend(itertools.chain.from_iterable(struct.pack(">I", address) for address in addresses))
        data.extend(itertools.chain.from_iterable(operation.to_bytes() for operation in memory_operations))
        if len(data) > self.meta_info.max_input_bytes:
            raise NintendontException(f"Command too long: Max {self.meta_info.max_input_bytes} bytes, got {len(data)}")
        response = await self.__make_request(data)

        results: list[bytes | None] = []
        current_index = ((len(memory_operations) - 1) // 8 + 1)
        success_bytes = response[:current_index]
        for i, op in enumerate(memory_operations):
            index = i // 8
            if success_bytes[index] & (1 << (i % 8)):
                if op.is_read():
                    result = response[current_index:current_index + op.size]
                    assert len(result) == op.size, f"Result: {result.hex()}, expected {op.size} bytes at index {current_index}"
                    results.append(result)
                    current_index += op.size
                else:
                    results.append(b'')
            else:
                results.append(None)
        return results

    def _read_chunk_size(self):
        assert self.meta_info
        return self.meta_info.max_output_bytes - 16

    def _write_chunk_size(self):
        assert self.meta_info
        return self.meta_info.max_input_bytes - 16

    async def read_pointer(self, pointer: int, offset: int, byte_count: int):
        if byte_count == 0:
            return (await self.__request_operations([pointer], [NintendontOperation.make_read(0, 0, offset)]))[0]

        results: list[bytes] = []
        for i in range(0, byte_count, self._read_chunk_size()):
            result = (await self.__request_operations(
                [pointer],
                [NintendontOperation.make_read(0, min(byte_count - i, self._read_chunk_size()), offset + i)])
            )[0]
            if result is None:
                return None
            results.append(result)
        return b''.join(results)

    async def read_address(self, address: int, bytes_to_read: int):
        if bytes_to_read == 0:
            result = (await self.__request_operations([address], [NintendontOperation.make_read(0, 0)]))[0]
            if result is None:
                raise NintendontException(f"{address:x} -> {address + bytes_to_read:x} is not a valid for GC memory")
            return result

        results: list[bytes] = []
        for i in range(0, bytes_to_read, self._read_chunk_size()):
            result = (await self.__request_operations(
                [address + i],
                [NintendontOperation.make_read(0, min(bytes_to_read - i, self._read_chunk_size()))])
            )[0]
            if result is None:
                raise NintendontException(f"{address:x} -> {address + bytes_to_read:x} is not a valid for GC memory")
            results.append(result)
        return b''.join(results)

    async def write_pointer(self, pointer: int, offset: int, data: bytes):
        if data == b'':
            await self.__request_operations([pointer], [NintendontOperation.make_write(False, 0, b'', offset)])
            return

        for i in range(0, len(data), self._write_chunk_size()):
            await self.__request_operations(
                [pointer],
                [NintendontOperation.make_write(False, 0, data[i:i + self._write_chunk_size()], offset + i)
            ])

    # FIXME: Only read_address() raises on bad address. NintendontClient has the same asymmetry to maintain the same
    # behavior as DolphinClient
    async def write_address(self, address: int, data: bytes):
        if data == b'':
            await self.__request_operations([address], [NintendontOperation.make_write(False, 0, b'')])
            return

        for i in range(0, len(data), self._write_chunk_size()):
            await self.__request_operations(
                [address + i],
                [NintendontOperation.make_write(False, 0, data[i:i + self._write_chunk_size()])
            ])
