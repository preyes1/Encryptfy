# Ensures key is 16 bytes
def repeat_key(s):
    return (s * (16 // len(s) + 1))[:16]