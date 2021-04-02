import hashlib, datetime, codecs


def lilEndian(num, digit=8):
    # padding to even digits
    if len(hex(num)) % 2 != 0:
        hexNum = '0' + hex(num)[2:]
    else:
        hexNum = hex(num)[2:]
    ba = bytearray.fromhex(hexNum)
    ba.reverse()
    s = ''.join(format(x, '02x') for x in ba)
    return s.ljust(digit, '0')


def block_hash_less_than_target(block_hash, given_target):
    return int(block_hash, 16) < int(given_target, 16)


def get_header_bin(version, prev_block, merkle_root, timestamp, size_bits, nonce):
    header_hex = \
        version + \
        prev_block + \
        merkle_root + \
        timestamp + \
        size_bits + \
        nonce

    header_bin = codecs.decode(header_hex, 'hex')
    return header_bin


def get_header_second_hash_big_endian_hex(header_bin):
    # Apply double-SHA-256
    first_hash_bin = hashlib.sha256(header_bin).digest()
    second_hash_bin = hashlib.sha256(first_hash_bin).digest()
    second_hash_big_endian = second_hash_bin[::-1]
    header_second_hash_big_endian_hex = second_hash_big_endian.hex()

    return header_second_hash_big_endian_hex


def mine(version, prev_block, merkle_root, _timestamp, bits):
    # Collect the new transactions into a block
    # Version: 4 bytes
    # Previous Block Hash: 32 bytes # Merkle Root: 32 bytes
    # Timestamp: 4 bytes # Difficulty Target: 4 bytes # Nonce: 4 bytes
    nonce = int(input('Please input nonce: '), 16)
    timestamp = int(datetime.datetime.strptime(_timestamp, "%Y-%m-%d %H:%M:%S").timestamp())
    timestampHex = lilEndian(timestamp, 8)
    merklerootHex = lilEndian(int(merkle_root, 16), 64)
    prevBlockHex = lilEndian(int(prev_block, 16), 64)
    nonceHex = lilEndian(nonce)
    versionHex = lilEndian(version)
    print('Nonce:', str(hex(nonce)))
    res = get_header_bin(versionHex, prevBlockHex, merklerootHex, timestampHex, lilEndian(bits, 8), nonceHex)
    # Find the valid nonce if the hash starts with enough zeros
    doubled_hash = get_header_second_hash_big_endian_hex(res)
    print('Block hash:', doubled_hash)
