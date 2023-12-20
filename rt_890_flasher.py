#!/bin/python

import sys
import argparse

import serial # type: ignore[import-untyped]

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
        except Exception as e: # pylint: disable=broad-exception-caught
            sys.exit(e)

        self.verbosity = verbosity

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):

        if exception_value:
            print(exception_value, file=sys.stderr)
            return True

        self.close()

    def close(self):
        self.port.close()

    def check_bootloader_mode(self):
        payload = [type(self).CMD_READ_FLASH, 0, 0]
        payload = type(self).prepare_transfer(payload)

        print(f"CMD Read:\n{bytes_format_str(payload, 16)}")

        self.port.write(payload)

        data_read = bytearray(self.port.read(4))

        # empty the input buffer, should be empty already,
        # though, and maybe recover from a timeout!

        for _i in range(8):
            while self.port.in_waiting:
                data_read += bytearray(self.port.read())

        if len(data_read) == 0:
            return False

        print(f"Response:\n{bytes_format_str(data_read, 16)}\n")


        return data_read[0] == 0xFF

    def cmd_erase_flash(self):
        payload = [type(self).CMD_ERASE_FLASH, 0, 0, 0x55]
        payload = type(self).prepare_transfer(payload)

        print(f"CMD Erase:\n{bytes_format_str(payload, 16)}")

        self.port.write(payload)
        response = self.read_one()

        if len(response) == 0:
            return False

        print(f"Response:\n{bytes_format_str(response, 16)}")

        return response == type(self).ACK_RESPONSE

    def cmd_write_flash(self, offset, bytes_128):
        if len(bytes_128) > type(self).FLASH_CHUNK_SIZE:
            raise Exception(f"FAILED: would choke on that 0x{len(bytes_128):05X} bytes chunk") # pylint: disable=broad-exception-raised

        payload = [type(self).CMD_WRITE_FLASH, (offset >> 8) & 0xFF, (offset >> 0) & 0xFF]
        payload += bytes_128
        payload = type(self).prepare_transfer(payload)

        self.port.write(payload)
        response = self.read_one()

        if len(response) == 0:
            return False

        if self.verbosity > 0:
            print(f"FLASHING at 0x{offset:05X} response:\n{bytes_format_str(response, 16)}")

        return response == type(self).ACK_RESPONSE

    def read_one(self):
        return self.port.read(1)

    def flash_firmware(self, fw_bytes):
        chunks = [
            [offset, fw_bytes[offset : offset + type(self).FLASH_CHUNK_SIZE]]
            for offset in range(0, len(fw_bytes), type(self).FLASH_CHUNK_SIZE)
        ]

        total_bytes = 0
        for chunk in chunks:
            if self.verbosity > 0:
                print(f"\nBytes at 0x{chunk[0]:05X}:")

            if len(chunk[1]) < type(self).FLASH_CHUNK_SIZE:
                chunk[1] += bytearray([0x0] * (type(self).FLASH_CHUNK_SIZE - len(chunk[1])))
                print("Note: Padding FW chunk with zeroes to align it to 0x80 bytes.")

            if self.verbosity > 0:
                print(bytes_format_str(chunk[1], 16))

            ok = self.cmd_write_flash(*chunk)
            print(f"FLASHING at 0x{chunk[0]:05X}, length: 0x{len(chunk[1]):02X}, result: {'OK' if ok else 'FAILED'}")

            if not ok:
                break

            total_bytes += len(chunk[1])

        print(f"Flashed a total of {total_bytes} (0x{total_bytes:0X}) bytes.")
        return total_bytes

def bytes_format_str(byte_array, step):
    bytes_splitted = [byte_array[off:off + step] for off in range(0, len(byte_array), step)]
    formatted_bytes = [ ",".join([f"0x{byte:02X}" for byte in _bytes]) for _bytes in bytes_splitted]
    formatted_bytes = [ f"0x{off * step:02X} | {_bytes}" for off, _bytes in enumerate(formatted_bytes)]
    header = f" Off | {' '.join([f'0x{i:02X}' for i in range(min(step, len(byte_array)))])}"
    separator = "=" * len(formatted_bytes[0])
    separator = separator[:5] + "|" + separator[6:]
    return "{}\n{separator}\n{}\n{separator}".format(header,'\n'.join(formatted_bytes), separator=separator)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="A tool for flashing RT-890 (and clones) firmware.\nFirst, put your radio on flashing mode by turning it on while pressing both Side-Keys.",
        epilog="RT-890 Firmware Flasher (c) 2023 JuantAldea (https://github.com/JuantAldea)",
    )

    parser.add_argument("serial_port", help="serial port where the radio is connected.")
    parser.add_argument("firmware_file", help="file containing the firmware.")
    parser.add_argument("-v", "--verbose", help="set verbose output", action="store_true",
        dest="verbose", default=False)

    if len(sys.argv) < 2:
        parser.print_help()
        exit(0)

    args = parser.parse_args()

    with RT890_Flasher(args.serial_port, args.verbose) as flasher:
        file = open(args.firmware_file, "rb")
        fw = file.read()
        file.close()

        print(f"Firmware size {len(fw)} (0x{len(fw):0X}) bytes")

        if not flasher.check_bootloader_mode():
            sys.exit("FAILED: Radio not on flashing mode, or not connected.")

        if not flasher.cmd_erase_flash():
            sys.exit("FAILED: Could not erase radio flash.")

        flashed_bytes = flasher.flash_firmware(fw)
        fw_chunk_overflow = len(fw) % 0x80
        padding = (flasher.FLASH_CHUNK_SIZE - fw_chunk_overflow) if fw_chunk_overflow else 0
        fw_size_aligned_to_chunk_size = len(fw) + padding

        if flashed_bytes != fw_size_aligned_to_chunk_size:
            sys.exit(f"FAILED: The amount of flashed bytes does not match the FW size padded to 0x80 (0x{fw_size_aligned_to_chunk_size:05X}).")

        print("All OK!")

        if fw_chunk_overflow:
            NOTE_STR = "# Note: The FW does not fill the whole memory. You have to reset the radio. #"
            FRAME ="#"*len(NOTE_STR)
            print(f"{FRAME}\n{NOTE_STR}\n{FRAME}")
