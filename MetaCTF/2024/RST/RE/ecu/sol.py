def decode_hash1_stage1(hash1):
    return (((hash1 ^  0x5A5A5A5A )) / 0x1F1F1F1F) & 0xFFFFFFFF


data = 0xadadadb4
