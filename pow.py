import hashlib
import datetime
import struct


def lilEndian(num, digit):
    # padding to even digits
    if len(hex(num)) % 2 != 0:
        hexNum = '0'+hex(num)[2:]
    else:
        hexNum = hex(num)[2:]
    ba = bytearray.fromhex(hexNum)
    ba.reverse()
    s = ''.join(format(x, '02x') for x in ba)
    return s.ljust(digit, '0')


def get_sha_256_hash(input_value):
    return hashlib.sha256(input_value).hexdigest()


def block_hash_less_than_target(block_hash, given_target):
    return int(block_hash, 16) < int(given_target, 16)


def mine(version, prev_block, merkle_root, _timestamp, bits):
    # Collect the new transactions into a block
    # Version: 4 bytes
    # Previous Block Hash: 32 bytes
    # Merkle Root: 32 bytes
    # Timestamp: 4 bytes
    # Difficulty Target: 4 bytes
    # Nonce: 4 bytes
    timestamp = int(datetime.datetime.strptime(_timestamp, "%Y-%m-%d %H:%M:%S").timestamp())
    timestampHex = lilEndian(timestamp, 8)
    blockData = '01000000' + prev_block + merkle_root + timestampHex + hex(bits)[2:]

    difficulty = 10
    target = '0x'+'0'*difficulty+'F'*(64-difficulty)

    mined = False

    nonce = 0

    while not mined:
        print('Nonce:', str(hex(nonce)))

        nonceHex = lilEndian(nonce, 8)
        blockDataHexWithNonce = int((blockData+nonceHex).encode(), 16)
        # Apply double-SHA-256
        doubled_hash = get_sha_256_hash(get_sha_256_hash(hex(blockDataHexWithNonce).encode()).encode())
        mined = block_hash_less_than_target(doubled_hash, target)

        if not mined:
            nonce += 1
        else:
            print('Solution Founded!')
            print('=>Block hash:', doubled_hash)