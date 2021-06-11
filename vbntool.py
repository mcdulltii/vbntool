import os
import sys
import logging
import hashlib
import argparse
from datetime import datetime
from struct import unpack

import logline

parser = argparse.ArgumentParser(description="Parse a Symantec Quarantine File (*.vbn)")
parser.add_argument("vbn_file", help="Provide a .vbn file to extract information from")
parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
parser.add_argument("-l", "--logline", help="Displays metadata from the embedded log line", action="store_true")
parser.add_argument("-i", "--ignore", help="Extract quarantine file even if hash does not match", action="store_true")
parser.add_argument("-o", "--output", help="Name to save quarantined file as. Defaults to original name if this flag is provided without a value", const=True, nargs="?")
parser.add_argument("-d", "--disable", help="Disable XOR decryption routine", action="store_true")
args = parser.parse_args()

CHUNK_SIZE = 1024

def read_chunks(filename, chunk_size = CHUNK_SIZE):
    '''
    Read file by chunks
    Default chunk size: 1k.
    '''
    while True:
        data = filename.read(chunk_size)
        if not data:
            break
        yield [chr(i) for i in data]

def xor(data, key):
    '''
    XOR data with key
    '''
    new_data = bytearray()
    for i in data:
        new_data.append(ord(i) ^ int(key, 16))
    return new_data

# Initialise logging
logger = logging.getLogger("vbntool")
if args.verbose:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

# Logging handler
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter("[%(levelname)-5s] %(message)s"))
logger.addHandler(ch)

# Open VBN file
input_file = open(args.vbn_file, "rb")
vbn = input_file.read()
logger.info("Loaded {} ({} bytes)".format(args.vbn_file, len(vbn)))

# Check for VBN magic header
if bytes(vbn[0:4]) != b'\x90\x12\x00\x00':
    logger.warning("First 4 bytes should be 0x90120000 but is {}".format(bytes(vbn[0:4])))

# Retrieve quarantine filepath
qfile_path = vbn[4:4+384].decode("utf-8").strip("\x00")
logger.info("Quarantined File was at: {}".format(qfile_path))

# Parse metadata
record_data = bytes(vbn[4 + 384 : 4 + 384 + 0x800]).decode("ascii").replace("\0", "")
info = logline.parse_log_line(record_data)
if args.logline:
    for key, value in info.items():
        if not key: continue
        logger.info("[LOG] {}: {}".format(key, value))

# based on observations of my samples
quarantine_time = datetime.fromtimestamp(unpack("<L", vbn[0xd70 : 0xd74])[0])
logger.info("Quarantine File created at {}".format(quarantine_time.isoformat()))

# Retrieve quarantine file address
qfm_offset = unpack("<L", vbn[0:4])[0]

# Lazily check if file is quarantined using Version 1
isVersion1 = False
qfile = None
if (unpack("<Q", xor([chr(i) for i in vbn[qfm_offset+24:qfm_offset+32]], '0x5A'))[0] >= len(vbn)):
    logger.info("Quarantine File metadata is missing. File might be encoded using Version 1 format.")
    isVersion1 = True

if not isVersion1:
    qf = bytearray()
    for b in vbn[qfm_offset:]:
        qf.append(b ^ 0x5A)

    # https://malwaremaloney.blogspot.com/2018/03/symantec-endpoint-protection-vbn-files.html
    # offsets below are calculated relative to qfm_size which is 0x1B27 (6951) in the above article

    qfm_size = unpack("<Q", qf[24:32])[0]
    logger.debug("Quarantine File Metadata & Header starts at offset {} ({}) size {} ({})".format(
            qfm_offset, hex(qfm_offset),
            qfm_size, hex(qfm_size)
        ))

    qfile_sha1 = bytes(qf[qfm_size + 12:qfm_size + 94]).decode("utf-16")[:-1]
    qfile_size = unpack("<Q", qf[qfm_size + 109:qfm_size + 109 + 8 ])[0]

    logger.info("Quarantined File has SHA1 hash: {}".format(qfile_sha1))
    logger.info("Quarantined File has size: {} bytes".format(qfile_size))

    # tracks the start of the current section that we're parsing
    section_index = qfm_size + 117

    qfile = bytearray()
    while section_index < len(qf):
        # first byte denotes type of section
        if qf[section_index] == 0x08:
            logger.debug("Parsing security section")
            security_descriptor_size = unpack("<L", qf[section_index + 1:section_index + 1 + 4])[0]
            security_descriptor = bytes(qf[section_index + 5:section_index + 5 + security_descriptor_size]).decode("utf-16")
            # 1: section index
            # 4: size of security descriptor
            # 5: unknown
            # 1: unknown
            # 8: original quarantined file size
            section_index += 1 + 4 + security_descriptor_size + 5 + 1 + 8
        elif qf[section_index] == 0x09:
            section_size = unpack("<L", qf[section_index + 1:section_index + 1 + 4])[0]
            logger.debug("Parsing data section of size {} from offset {} to {}".format(section_size, qfm_offset + section_index, qfm_offset + section_index + 5 + section_size))

            section_end = section_index + 5 + section_size
            if section_end > len(qf):
                logger.warning("Need to read up to offset {} but data is only {} bytes long".format(section_end, len(qf)))

            section_data = qf[section_index + 5 : section_end]

            # section_data is actually XORed with 0xA5
            # since we've already XORed it with 0x5A, undo it
            for b in section_data:
                qfile.append(b ^ 0x5A ^ 0xA5)

            section_index += 1 + 4 + section_size
        else:
            raise Exception("Unknown section header: {}".format(hex(qf[section_index])))

    qfile_actual_sha1 = hashlib.sha1(qfile).hexdigest()
    if qfile_sha1.lower() != qfile_actual_sha1.lower():
        logger.warning("Actual SHA1({}) of the quarantined file does not match stated SHA1({})!".format(qfile_actual_sha1, qfile_sha1))

        if not args.ignore:
            if args.output:
                logger.warning("Pass -i/--ignore to extract the quarantined file anyway")
            sys.exit()

    logger.info("Quarantine file hash verified ok")

if args.output:
    if args.output == True:
        out_name = os.path.basename(qfile_path)
    else:
        out_name = args.output

    logger.info("Writing {} bytes to {}".format(len(qfile) if qfile else len(vbn[qfm_offset:]), out_name))
    with open(out_name, "wb") as f:
        if isVersion1:
            input_file.seek(qfm_offset)
            for piece in read_chunks(input_file):
                # Check if XOR decryption is enabled
                if (args.disable == True):
                    output = xor(piece, '0x0')
                else:
                    output = xor(piece, '0x5A')
                f.write(output)
        else:
            f.write(bytes(qfile))
else:
    logger.info("Pass -o/--output to extract the quarantined file")
