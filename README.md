

<p align="center">
  <img src="./.image/banner_mag.png" alt="banner">
</p>


---

<p align="center">
    <img alt="Version" src="https://img.shields.io/badge/Version-0.1-blue.svg" />
    <img alt="Compiler" src="https://img.shields.io/badge/Compiler-GCC-green.svg" />
    <img alt="Linker" src="https://img.shields.io/badge/Linker-GCC-green.svg" />
    <img alt="Encryptor" src="https://img.shields.io/badge/Encryptor-ascii-red.svg" />
    <img alt="Name" src="https://img.shields.io/badge/Magnetar-8A2BE2" />
    <a href="https://0xjrx.github.io/magnetar/"><img alt="Docs" src="https://img.shields.io/badge/Docs-Doxygen-8A2BE2.svg" /></a>
</p>

Magnetar is a sophisticated shellcode loader framework for Windows 10 64bit, featuring advanced encryption and obfuscation, ETW and AMSI patching, as well as process protection and direct syscalls through tartarus gate for hook evasion.

The basis of this framework was developed by me, [0xjrx](https://github.com/0xjrx) as part of my bachelors thesis. Magnetar is the advanced version of this, which I adjusted and rewrote in my free time. This project is WIP and only for educational purposes. Because the original implementation could bypass Sophos EDR, the project ships **without** the critical syscall component (dynamic hashing/direct syscalls).
If you rebuild or reuse Magnetar you’ll need to supply your own syscall module. 


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

### Planned Features
- **Module Stomping**: Instead of writing shellcode to a processes address space, load and stomp a given module with shellcode
- **DLL Injection**: As of now, the result is a shellcode loader, however, DLL injection (reflective etc.) may be even more advanced. I want to implement that in further updates
- **Certificate Spoofing**: Sign the binary with a spoofed Cert to make it appear legit
- **Stack spoofing**: Instead of creating pretty much textbook IOC stackframes, use 'SilentMoonWalk' or 'LoudSunRun' to spoof callstacks
- **Beacon functionality**: As of now normal shellcodes and meterpreter payloads work, I want to add my own payload/beacon and maybe add sleep obfuscation to evade memory scanners
- **BYOVD (Bring your own vulnerable driver)**: Utilize vulnerable drivers to elevate privileges
- **PE Payloads**: Functionality to encrypt and load whole PE files through the loader
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
│
├── build/                 # Generated headers & binaries
│   ├── data.h             # Encrypted shellcode (generated)
│   └── syscalls.h         # Generated syscall hashes
│
├── common/                # Python utilities used by builder
│   ├── __init__.py        # package initializer
│   ├── crypto.py          # RC4, key encryption routines
│   ├── encoder.py         # ascii encoding helpers
│   └── helper.py          # small utility functions (file I/O, etc.)
│
├── include/               # Public C headers (used with -Iinclude)
│   ├── crypto/
│   │   ├── decryptor.h
│   │   └── rc_crypt.h
│   ├── decode/
│   │   └── decode.h
│   ├── enum/
│   │   └── enum.h
│   ├── patches/
│   │   └── patch.h
│   ├── syscall/
│   │   ├── HellsGate.h    # Removed to prevent misuse
│   │   └── structs.h      # Removed to prevent misuse
│   └── util/
│       └── util.h         # logging 
│
├── src/                   # C implementation code
│   ├── main.c             # Entry point (formerly loader.c)
│   └── modules/
│       ├── crypto/
│       │   ├── decryptor.c
│       │   └── rc_crypt.c
│       ├── decode/
│       │   └── decode.c
│       ├── enum/
│       │   └── enum.c
│       ├── patches/
│       │   └── patch.c
│       └── syscall/
│           ├── HellsGate.asm # Removed to prevent misuse
│           ├── HellsGate.c   # Removed to prevent misuse
│           └── HellGate.obj  # Removed to prevent misuse       
│
├── meta/                  # Resources and metadata
│   ├── meta.rc            # Recourcefile to be compiled with windres, includes metadata for binary
│   └── icons/
│       └── chrome.ico     # Icon used for metadata config, replace with your own
│
├── calc.bin               # Example shellcode payload
└── README.md              # This file
```

