from logging import Logger
import socket
import struct
from typing import Optional

from .BaseClient import GC_GAME_ID_ADDRESS, BaseClient, Prime1ClientException

NINTENDONT_PORT: int = 43673


class NintendontException(Prime1ClientException):
    pass


class NintendontClient(BaseClient):
    ip: str = ""
    client: socket.socket | None = None
    api_version: int = 0
    max_input: int = 0
    max_output: int = 0
    max_addresses: int = 0

    def __init__(self, logger: Logger, ip: str):
        super().__init__(logger)
        if ip == "":
            raise NintendontException("IP is not set")
        self.ip = ip
        self.client = None

    @property
    def internal_name(self):
        return "nintendont"

    @property
    def name(self):
        return "Nintendont"

    def is_connected(self):
        try:
            self.__assert_connected()
            return True
        except Exception:
            return False

    def connect(self):
        try:
            if self.client is None:
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client.connect((self.ip, NINTENDONT_PORT))

                # Querying API stuff
                self.client.send(struct.pack(">BBBB", 1, 0, 0, 1))
                self.api_version, self.max_input, self.max_output, self.max_addresses = struct.unpack_from(">IIII", self.client.recv(1024), 0)

            if self.client is None:
                raise Exception()
        except:
            self.disconnect()
            raise NintendontException(
                "Could not connect to Nintendont, verify that you have a game running and that your console is connected to the network")

    def disconnect(self):
        try:
            if self.client is not None:
                self.client.close()
        except:
            pass
        self.client = None
        self.api_version = 0
        self.max_input = 0
        self.max_output = 0
        self.max_addresses = 0

    def __assert_connected(self):
        """Custom assert function that returns a NintendontException instead of a generic RuntimeError if the connection is lost"""
        try:
            # this will try to read bytes without blocking and also without removing them from buffer (peek only)
            data = self.client.recv(16, socket.MSG_DONTWAIT | socket.MSG_PEEK)
            if len(data) == 0:
                return
            self.disconnect()
        except BlockingIOError: # socket is open and reading from it would block
            return
        except ConnectionResetError: # socket was closed for some other reason
            self.disconnect()
        except Exception as e:
            return

    def _build_packet(self, address: int, offset: Optional[int] = None, read_byte_count: Optional[int] = None, write_bytes: Optional[bytes] = None) -> bytes:
        def _byte_count(read_byte_count: Optional[int], write_bytes: Optional[bytes]) -> int:
            if read_byte_count is not None:
                return read_byte_count
            if write_bytes is not None:
                return len(write_bytes)
            return 0

        header = struct.pack(f">BBBB1I", 0, 1, 1, 1, address)
        byte_count = _byte_count(read_byte_count, write_bytes)
        op_byte = 0
        if read_byte_count is not None:
            op_byte |= 0x80
        if write_bytes is not None:
            op_byte |= 0x40
        if byte_count == 4:
            op_byte |= 0x20
        if offset is not None:
            op_byte |= 0x10
        data = struct.pack(">B", op_byte)
        if byte_count != 4:
            data += struct.pack(">B", byte_count)
        if offset is not None:
            data += struct.pack(">h", offset)
        if write_bytes is not None:
            data += write_bytes
        return header + data

    def read_pointer(self, pointer, offset, byte_count):
        self.__assert_connected()

        address = None
        try:
            address = struct.unpack(">I", self.read_address(pointer, 4))[0]
        except RuntimeError:
            return None

        if self.client is None:
            raise NintendontException("Nintendont no longer connected")

        address += offset
        return self.read_address(address, byte_count)

    def read_address(self, address, bytes_to_read):
        self.__assert_connected()
        self.verify_target_address(address, bytes_to_read)

        try:
            self.client.send(self._build_packet(address, read_byte_count=bytes_to_read))
            result = self.client.recv(1024)
        except:
            raise RuntimeError(f"Couldn't write at address {address:X}!")

        # has operation succeeded?
        if result[0] == 0:
            raise RuntimeError(f"Couldn't read at address {address:X}!")

        return result[1:]

    def write_pointer(self, pointer, offset, data):
        self.__assert_connected()
        address = None
        try:
            address = struct.unpack(">I", self.read_address(pointer, 4))[0]
        except RuntimeError:
            return None

        if self.client is None:
            raise NintendontException("Nintendont no longer connected")

        address += offset
        return self.write_address(address, data)

    def write_address(self, address, data):
        self.__assert_connected()
        try:
            self.client.send(self._build_packet(address, write_bytes=data))
            result = self.client.recv(1024)
        except:
            raise RuntimeError(f"Couldn't write at address {address:X}!")

        # has operation succeeded?
        if result[0] == 0:
            raise RuntimeError(f"Couldn't write at address {address:X}!")

        return result[1:]
