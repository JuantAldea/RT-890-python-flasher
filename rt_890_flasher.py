#!/bin/python

import sys
import argparse

import serial  # type: ignore[import-untyped]


class RT890Flasher:
    ACK_RESPONSE = 0x06.to_bytes()
    FLASH_MODE_RESPONSE = 0xFF
    CMD_ERASE_FLASH = 0x39
    CMD_READ_FLASH = 0x52
    CMD_WRITE_FLASH = 0x57
    WRITE_BLOCK_SIZE = 0x80
    MEMORY_SIZE = 0xEC00

    @classmethod
    def append_checksum(cls, data):
        data.append(sum(data) % 256)
        return bytearray(data)

    def __init__(self, serial_port, verbosity=1):
        try:
            self.port = serial.Serial(
                port=serial_port,
                baudrate=115200,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                bytesize=serial.EIGHTBITS,
                write_timeout=2000,
                timeout=3,
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            sys.exit(e)

        self.verbosity = verbosity

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        if exception_value:
            print(exception_value, file=sys.stderr)
            return True

        self.close()
        return None

    def close(self):
        self.port.close()

    def check_bootloader_mode(self):
        # discard any leftovers
        while self.port.in_waiting:
            self.port.read()

        payload = [self.CMD_READ_FLASH, 0, 0]
        payload = self.append_checksum(payload)

        print(f"CMD Read:\n{hexdump(payload, 32)}")

        self.port.write(payload)

        data_read = bytearray(self.port.read(4))

        # empty the input buffer, should be empty already
        # though, and maybe recover from a timeout

        for _i in range(8):
            while self.port.in_waiting:
                data_read += bytearray(self.port.read())

        if not data_read:
            return False

        print(f"Response:\n{hexdump(data_read, 32)}\n")

        return data_read[0] == self.FLASH_MODE_RESPONSE

    def cmd_erase_flash(self):
        payload = [self.CMD_ERASE_FLASH, 0, 0, 0x55]
        payload = self.append_checksum(payload)

        print(f"CMD Erase:\n{hexdump(payload, 32)}")

        self.port.write(payload)
        response = self.port.read(1)

        if not response:
            return False

        print(f"Response:\n{hexdump(response, 32)}")

        return response == self.ACK_RESPONSE

    def cmd_write_flash(self, offset, bytes_128):
        if len(bytes_128) != self.WRITE_BLOCK_SIZE:
            raise AssertionError(
                (
                    "FAILED: FW chunk does not have the correct size. "
                    f"Got 0x{len(bytes_128):02X} bytes, expected 0x{self.WRITE_BLOCK_SIZE:02X}."
                )
            )

        payload = [self.CMD_WRITE_FLASH, (offset >> 8) & 0xFF, (offset >> 0) & 0xFF]
        payload += bytes_128
        payload = self.append_checksum(payload)

        self.port.write(payload)
        response = self.port.read(1)

        if not response:
            return False

        if self.verbosity > 0:
            print(f"Writting at 0x{offset:04X} response:\n{hexdump(response, 32)}")

        return response == self.ACK_RESPONSE

    def flash_firmware(self, fw_bytes):
        last_chunk_size = len(fw_bytes) % self.WRITE_BLOCK_SIZE
        padding_to_add = (
            self.WRITE_BLOCK_SIZE - last_chunk_size if last_chunk_size else 0
        )

        if padding_to_add:
            print(
                f"Note: Padding with {padding_to_add} ZERO-bytes to align the FW to 0x80 bytes."
            )

            fw_bytes += bytearray([0x0] * padding_to_add)

        chunks = [
            [offset, fw_bytes[offset : offset + self.WRITE_BLOCK_SIZE]]
            for offset in range(0, len(fw_bytes), self.WRITE_BLOCK_SIZE)
        ]

        total_bytes = 0
        for chunk in chunks:
            if self.verbosity > 0:
                print(f"\nBytes at 0x{chunk[0]:04X}:")

            if self.verbosity > 0:
                print(hexdump(chunk[1], 32))

            ok = self.cmd_write_flash(*chunk)

            print(
                (
                    f"Writting at 0x{chunk[0]:04X}, "
                    f"length: 0x{len(chunk[1]):02X}, "
                    f"result: {'OK' if ok else 'FAILED'}"
                )
            )

            if not ok:
                break

            total_bytes += len(chunk[1])

        print(f"Written a total of {total_bytes} (0x{total_bytes:0X}) bytes.")
        return (total_bytes, padding_to_add)


def hexdump(byte_array, step):
    dump = [byte_array[off : off + step] for off in range(0, len(byte_array), step)]
    dump = [" ".join([f"{byte:02X}" for byte in _bytes]) for _bytes in dump]
    dump = [f"{off * step:03X} | {_bytes}" for off, _bytes in enumerate(dump)]

    header = (
        f"Off | {' '.join([f'{i:02X}' for i in range(min(step, len(byte_array)))])}"
    )

    separator = ["="] * len(dump[0])
    separator[4] = "|"
    separator = "".join(separator)

    return "{}\n{separator}\n{}\n{separator}".format(
        header, "\n".join(dump), separator=separator
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "A tool for programming RT-890 (and clones) firmware.\nFirst, "
            "put your radio on programming mode by turning it on while pressing both Side-Keys."
        ),
        epilog="RT-890 Firmware Programmer (c) 2023 JuantAldea (https://github.com/JuantAldea)",
    )

    parser.add_argument("serial_port", help="serial port where the radio is connected.")
    parser.add_argument("firmware_file", help="file containing the firmware.")
    parser.add_argument(
        "-v",
        "--verbose",
        help="set verbose output",
        action="store_true",
        dest="verbose",
        default=False,
    )

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    with RT890Flasher(args.serial_port, args.verbose) as flasher:
        with open(args.firmware_file, "rb") as file:
            fw = file.read()

        fw_len = len(fw)
        print(f"Firmware size {fw_len} (0x{fw_len:04X}) bytes")

        if not flasher.check_bootloader_mode():
            sys.exit("\nFAILED: Radio not on flashing mode, or not connected.")

        if not flasher.cmd_erase_flash():
            sys.exit("\nFAILED: Could not erase radio memory.")

        flashed_bytes, added_padding = flasher.flash_firmware(fw)
        padded_fw_size = fw_len + added_padding
        if flashed_bytes != padded_fw_size:
            sys.exit(
                (
                    "\nFAILED: The amount of bytes written does not match the "
                    f"FW size padded to 0x80. "
                    f"Expected {padded_fw_size} (0x{padded_fw_size:04X}) bytes, "
                    f"wrote: {flashed_bytes} (0x{flashed_bytes:04X})."
                )
            )

        print("\nAll OK!")

        if flashed_bytes != RT890Flasher.MEMORY_SIZE:
            NOTE_STR = (
                "# Note: The FW does not fill the whole memory."
                " The radio will not restart automatically. #"
            )
            FRAME = "#" * len(NOTE_STR)
            print(f"{FRAME}\n{NOTE_STR}\n{FRAME}")
