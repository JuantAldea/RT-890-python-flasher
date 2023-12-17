#!/bin/python

import sys
import serial

class RT890_Flasher:
    ACK_RESPONSE = 0x06.to_bytes()
    CMD_ERASE_FLASH = 0x39
    CMD_READ_FLASH = 0x52
    CMD_WRITE_FLASH = 0x57
    FLASH_CHUNK_SIZE = 128

    @classmethod
    def prepare_transfer(cls, data):
        data.append(cls.calculate_checksum(data))
        return bytearray(data)

    @classmethod
    def calculate_checksum(cls, data):
        return sum(data) % 256

    def __init__(self, serial_port, verbosity=1):
        self.port = serial.Serial(
            port=serial_port,
            baudrate=115200,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            write_timeout=2000,
            timeout=3,
        )
        self.verbosity = verbosity

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.close()

    def close(self):
        self.port.close()

    def check_bootloader_mode(self):
        payload = [type(self).CMD_READ_FLASH, 0, 0]
        payload = type(self).prepare_transfer(payload)

        print("CMD Read:")
        print_bytes(payload, 16)

        self.port.write(payload)

        data_read = bytearray(self.port.read(4))

        # empty the input buffer, should be empty already, though, and maybe recover from a timeout!
        for _i in range(8):
            while self.port.in_waiting:
                data_read += bytearray(self.port.read())

        if len(data_read) == 0:
            return False

        print("Response:")
        print_bytes(data_read, 16)

        return data_read[0] == 0xFF

    def cmd_erase_flash(self):
        payload = [type(self).CMD_ERASE_FLASH, 0, 0, 0x55]
        payload = type(self).prepare_transfer(payload)

        print("CMD Erase:")
        print_bytes(payload, 16)

        self.port.write(payload)
        response = self.read_one()

        if len(response) == 0:
            return False

        print("Response:")
        print_bytes(response, 16)

        return response == type(self).ACK_RESPONSE

    def cmd_write_flash(self, offset, bytes_128):
        if len(bytes_128) > type(self).FLASH_CHUNK_SIZE:
            raise Exception("Would choke on that chunk")

        payload = [type(self).CMD_WRITE_FLASH, (offset >> 8) & 0xFF, (offset >> 0) & 0xFF]
        payload += bytes_128
        payload = type(self).prepare_transfer(payload)

        self.port.write(payload)
        response = self.read_one()

        if len(response) == 0:
            return False

        if self.verbosity > 0:
            print(f"FLASH at 0x{offset:05X} response:")
            print_bytes(response, 16)

        return response == type(self).ACK_RESPONSE

    def read_one(self):
        return self.port.read(1)

    def flash_firmware(self, fw_bytes):
        chunks = [
            (offset, fw_bytes[offset : offset + type(self).FLASH_CHUNK_SIZE])
            for offset in range(0, len(fw_bytes), type(self).FLASH_CHUNK_SIZE)
        ]

        total_bytes = 0
        for chunk in chunks:

            if self.verbosity > 0:
                print(f"\nBytes at 0x{chunk[0]:05X}:")
                print_bytes(chunk[1], 16)

            ok = self.cmd_write_flash(*chunk)
            print(f"FLASH at 0x{chunk[0]:05X}, length: 0x{len(chunk[1]):02X}, result: {'OK' if ok else 'Failed'}")

            if not ok:
                break

            total_bytes += len(chunk[1])

        print(f"Flashed a total of {total_bytes} (0x{total_bytes:0X}) bytes")
        return total_bytes

def print_bytes(byte_array, step):
    bytes_splitted = [byte_array[off:off + step] for off in range(0, len(byte_array), step)]
    formatted_bytes = [ ",".join([f"0x{byte:02X}" for byte in _bytes]) for _bytes in bytes_splitted]
    formatted_bytes = [ f"0x{off * step:02X} | {_bytes}" for off, _bytes in enumerate(formatted_bytes)]
    header = f" Off | {' '.join([f'0x{i:02X}' for i in range(min(step, len(byte_array)))])}"
    separator = "=" * len(formatted_bytes[0])
    separator = separator[:5] + "|" + separator[6:]
    print(header)
    print(separator)
    print("\n".join(formatted_bytes))
    print(separator)
    print("")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Radtel RT-890 programmer (c) 2023 JuantAldea (https://github.com/JuantAldea)\n")
        print("First put your radio on flashing mode by turning it on while pressing both Side-Keys.\n")
        print(f"Usage:\n\t{sys.argv[0]} <serial_port> <firmware_file>\n")
        sys.exit(0)

    with RT890_Flasher(sys.argv[1], verbosity=1) as flasher:
        file = open(sys.argv[2], "rb")
        fw = file.read()
        file.close()

        print(f"Firmware size {len(fw)} (0x{len(fw):0X}) bytes")

        if not flasher.check_bootloader_mode():
            print("Radio not on flashing mode, or not connected")
            sys.exit(-1)

        if not flasher.cmd_erase_flash():
            print("Could not erase flash")
            sys.exit(-1)

        flashed_bytes = flasher.flash_firmware(fw)

        if flashed_bytes != len(fw):
            sys.exit(-1)

        print("All OK!")
