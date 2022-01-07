#!/usr/bin/env python3
##
# 
# Python script to calculate firmware digests including
# injected hashes of initrd, kernel, and kernel params.
#
##
import sys
import os
import base64
import hashlib
from argparse import ArgumentParser
from uuid import UUID


SEV_HASH_TABLE_HEADER_GUID = "9438d606-4f22-4cc9-b479-a793d411fd21"

SEV_KERNEL_ENTRY_GUID = "4de79437-abd2-427f-b835-d5b172d2045b"
SEV_INITRD_ENTRY_GUID = "44baf731-3a2f-4bd7-9af1-41e29169781d"
SEV_CMDLINE_ENTRY_GUID = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a"

def guid_to_le(guid_str):
    return UUID("{" + guid_str + "}").bytes_le

def construct_sev_hashes_page(kernel_hash, initrd_hash, cmdline_hash):
    ht_len = 16 + 2 + 3 * (16 + 2 + 32)
    ht_len_aligned = (ht_len + 15) & ~15
    ht = bytearray(ht_len_aligned)

    # Table header
    ht[0:16] = guid_to_le(SEV_HASH_TABLE_HEADER_GUID)
    ht[16:18] = ht_len.to_bytes(2, byteorder='little')

    # Entry 0: kernel command-line
    e = 18
    ht[e:e+16] = guid_to_le(SEV_CMDLINE_ENTRY_GUID)
    ht[e+16:e+18] = (16 + 2 + 32).to_bytes(2, byteorder='little')
    ht[e+18:e+18+32] = cmdline_hash

    # Entry 1: initrd
    e = e+18+32
    ht[e:e+16] = guid_to_le(SEV_INITRD_ENTRY_GUID)
    ht[e+16:e+18] = (16 + 2 + 32).to_bytes(2, byteorder='little')
    ht[e+18:e+18+32] = initrd_hash

    # Entry 2: kernel
    e = e+18+32
    ht[e:e+16] = guid_to_le(SEV_KERNEL_ENTRY_GUID)
    ht[e+16:e+18] = (16 + 2 + 32).to_bytes(2, byteorder='little')
    ht[e+18:e+18+32] = kernel_hash

    return ht

def main(args):
    kernel_hash = None
    initrd_hash = None
    cmdline_hash = None
    sev_hashes_table = None

    if args.kernel:
        with open(args.kernel, 'rb') as fh:
            print("Calculating hash of kernel at {}".format(args.kernel))
            h = hashlib.sha256(fh.read())
            kernel_hash = h.digest()

    if args.initrd:
        with open(args.initrd, 'rb') as fh:
            print("Calculating hash of initrd at {}".format(args.initrd))
            h = hashlib.sha256(fh.read())
            initrd_hash = h.digest()

    if args.cmdline:
        print("Calculating hash of kernel params ({})".format(args.cmdline))
        cmdline = args.cmdline.encode() + b'\x00'
        h = hashlib.sha256(cmdline)
        cmdline_hash = h.digest()

    if kernel_hash and initrd_hash and cmdline_hash:
        sev_hashes_table = construct_sev_hashes_page(kernel_hash, initrd_hash, cmdline_hash)

    with open(args.ovmf, 'rb') as fh:
        h = hashlib.sha256(fh.read())
    if sev_hashes_table:
        h.update(sev_hashes_table)
    ovmf_hash = h.digest()
    print("Firmware Digest: {}".format(ovmf_hash.hex()))


if __name__ == "__main__":
    parser = ArgumentParser(description='Calculate firmware digest')

    parser.add_argument('--ovmf',
                        help='location of OVMF file to calculate hash from',
                        required=True)
    parser.add_argument('--kernel',
                        help='location of kernel file to calculate hash from')
    parser.add_argument('--initrd',
                        help='location of initrd file to calculate hash from')
    parser.add_argument('--cmdline',
                        help='the kernel command line to calculate hash from')

    args = parser.parse_args()
    main(args)


