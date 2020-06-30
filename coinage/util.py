from string import ascii_uppercase, ascii_lowercase

def is_mixed_case(s):
    return any(char in ascii_uppercase for char in s) and any(char in ascii_lowercase for char in s)
