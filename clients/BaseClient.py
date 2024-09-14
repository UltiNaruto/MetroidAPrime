from logging import Logger

GC_GAME_ID_ADDRESS = 0x80000000


class Prime1ClientException(Exception):
    pass


class BaseClient:
    logger: Logger

    def __init__(self, logger):
        self.logger = logger

    @property
    def internal_name(self):
        raise Prime1ClientException('Not implemented!')

    @property
    def name(self):
        raise Prime1ClientException('Not implemented!')

    def is_connected(self):
        raise Prime1ClientException('Not implemented!')

    def connect(self):
        raise Prime1ClientException('Not implemented!')

    def disconnect(self):
        raise Prime1ClientException('Not implemented!')

    def verify_target_address(self, target_address: int, read_size: int):
        """Ensures that the target address is within the valid range for GC memory"""
        if target_address < 0x80000000 or target_address + read_size > 0x81800000:
            raise Prime1ClientException(
                f"{target_address:x} -> {target_address + read_size:x} is not a valid for GC memory"
            )

    def read_pointer(self, pointer, offset, byte_count):
        raise Prime1ClientException('Not implemented!')

    def read_address(self, address, bytes_to_read):
        raise Prime1ClientException('Not implemented!')

    def write_pointer(self, pointer, offset, data):
        raise Prime1ClientException('Not implemented!')

    def write_address(self, address, data):
        raise Prime1ClientException('Not implemented!')
