"""
================================================================
Scratch Cryptography: Custom Hash Implementation
================================================================
"""

def scratch_hash(message: str | bytes) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    state = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    
    # Simple sponge mixing
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        for j in range(8):
            chunk = int.from_bytes(block[j*4:j*4+4], 'big')
            state[j] = (state[j] ^ chunk) & 0xFFFFFFFF
            state[j] = ((state[j] << 13) | (state[j] >> 19)) & 0xFFFFFFFF
            state[(j+1)%8] = (state[(j+1)%8] + state[j]) & 0xFFFFFFFF

    return "".join(f"{x:08x}" for x in state)

def custom_password_hash(password: str, salt: str) -> str:
    return scratch_hash(password + salt)
