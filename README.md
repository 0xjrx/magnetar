<p align="center">
  <img src="./.image/alternative.png" alt="banner">
</p>

---

<p align="center">
    <img alt="Version" src="https://img.shields.io/badge/Version-0.1-blue.svg" />
    <img alt="Compiler" src="https://img.shields.io/badge/Compiler-GCC-green.svg" />
    <img alt="Linker" src="https://img.shields.io/badge/Linker-GCC-green.svg" />
    <img alt="Encryptor" src="https://img.shields.io/badge/Encryptor-ascii-red.svg" />
    <img alt="Name" src="https://img.shields.io/badge/Magnetar-8A2BE2" />
</p>

Magnetar is a sophisticated shellcode loader framework for Windows 10 64bit, featuring advanced encryption and obfuscation, ETW and AMSI patching, as well as process protection and direct syscalls through tartarus gate for hook evasion.

The basis of this framework was developed by me, [0xjrx](https://github.com/0xjrx) as part of my bachelors thesis. Magnetar is the advanced version of this, which I adjusted and rewrote in my free time. This project is WIP and only for educational purposes. To prevent any script kiddies from using this framework (as it was able to bypass Sophos EDR) a critical syscall module, responsible for dynamic hashing and direct syscalls, has been removed. You must include your own module for that. 


## Features

### Encryption & Encoding
- **Ascii-based Encoding**: Text-based encoding for lower section entropy and obfuscation (Encrypt -> Encode to Ascii words)
- **Custom Key Support**: User-defined encryption keys for enhanced security

### Injection Techniques
- **Early Bird APC**: APC injection during process creation for better evasion with complete syscall obfuscation
- **Process Hypnosis**: Debug-based injection technique using Hell's Gate for memory operations

### Advanced Features
- **PPID Spoofing**: Parent Process ID spoofing for process ancestry deception
- **Process Enumeration**: Multiple methods for target process discovery with fallback mechanisms
- **Process Protection**: Proper process protection through modification of the process security descriptor
- **Anti-Analysis**: Various techniques to complicate reverse engineering
- **Resource Embedding**: Icon and metadata embedding for better disguise
- **ETW Patching**: Event Tracing for Windows bypass using Hell's Gate syscalls
- **AMSI Patching**: Antimalware Scan Interface bypass using Hell's Gate syscalls
- **Complete Syscall Obfuscation**: All critical operations use direct syscalls to avoid userland hooks

## Usage

```sh
python builder.py <input_shellcode> [options]
```

### Command Line Options

| Option | Choices | Default | Description |
|--------|---------|---------|-------------|
| `input` | file path | - | Path to the input shellcode file (e.g., `calc.bin`) |
| `--encryption` | `ascii` | Encryption/encoding mode |
| `--technique` |`eb`, `hypnosis`| Execution technique |
| `--target_process` | process name | `notepad.exe` | Target process for injection techniques |
| `--key` | string | `SecretKey1337` | Custom encryption key (5-256 characters) |
| `--spoof` | process name | `svchost.exe` | Process to spoof as parent (PPID spoofing) |
| `--clean` | flag | - | Clean build artifacts and exit |
| `--nodebug` | flag | - | This will result in the binary containing no print statements and their strings |
| `--noetw` | flag | - | Enable ETW patching using Hell's Gate syscalls |
| `--noamsi` | flag | - | Enable AMSI patching using Hell's Gate syscalls |
| `--antidebug` | flag | - | Enable anti-debugging features |
| `--protect` | flag | - | Change the security descriptor to protect the process |
| `--delay` | integer | `1` | Time to delay program execution (minutes) |

## Project Structure

```
magnetar/
├── builder.py             # Main build script
├── common/                # Shared utilities
│   ├── __init__.py        # Encryption and encoding functions
├── src/                   # Source code
│   ├── loader.c           # Main loader implementation
│   └── modules/
│       ├── crypto/        # Encryption/decryption modules
│       │   ├── decryptor.h
│       │   ├── decryptor.c
│       │   ├── rc_crypt.c
│       │   └── rc_crypt.h
│       ├── data/          # Generated data headers
│       │   └── data.h     # Encrypted shellcode (generated)
│       ├── decode/        # Decoding modules
│       │   ├── decode.c
│       │   └── decode.h
│       ├── enum/          # Process enumeration
│       │   ├── enum.c
│       │   └── enum.h
│       ├── icons/         # Application icons
│       │   └── chrome.ico
│       ├── meta/          # Metadata and resources
│       │   ├── meta.rc
│       │   ├── meta.res
│       │   └── meta.o
│       ├── patches/       # Module for patches, incl. ETW/AMSI
│           ├── patch.c
│       │   └── patch.h
│       └── syscall/       # System call modules
│           ├── HellsGate.asm
│           ├── HellsGate.c
│           ├── HellsGate.h
│           ├── HellsGate.obj
│           ├── syscalls.c
│           └── structs.h
├── calc.bin             # Example calc pop
└── README.md            # This file
```

---