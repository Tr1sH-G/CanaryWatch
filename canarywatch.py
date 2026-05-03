import os
import ctypes
import struct
import signal

# --- Linux Kernel Constants ---
# These are the "secret codes" the kernel uses to understand what we want
FAN_CLASS_CONTENT = 0x00000004
FAN_MARK_ADD = 0x00000001
FAN_OPEN_PERM = 0x00010000
FAN_DENY = 0x02
FAN_ALLOW = 0x01

# Load the standard Linux C library
libc = ctypes.CDLL("libc.so.6")

class FanotifyEventMetadata(ctypes.Structure):
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]

def start_trap(bait_path):
    # 1. Initialize Fanotify (The Gatekeeper)
    # This returns a "File Descriptor" (fd) which is our handle on the kernel
    fd = libc.fanotify_init(FAN_CLASS_CONTENT, os.O_RDONLY)
    if fd < 0:
        print("Error: Could not initialize fanotify. Are you running as sudo?")
        return

    # 2. Mark the bait file
    # We tell the kernel: "Watch this path for Open-Permission events"
    if libc.fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN_PERM, -100, bait_path.encode()) < 0:
        print(f"Error: Could not mark {bait_path}")
        return

    print(f"TRAP ARMED: Monitoring {bait_path}...")

    try:
        while True:
            # 3. Read the event from the kernel
            buf = os.read(fd, 4096)
            if not buf:
                break
            
            # Unpack the metadata (length of the metadata struct is 24 bytes)
            metadata = FanotifyEventMetadata.from_buffer_copy(buf[:24])
            
            if metadata.mask & FAN_OPEN_PERM:
                attacker_pid = metadata.pid
                print(f"INTRUDER! PID {attacker_pid} tried to open the file.")
                
                # 4. Neutralize the intruder
                try:
                    os.kill(attacker_pid, signal.SIGKILL)
                    print(f"Target {attacker_pid} killed.")
                except ProcessLookupError:
                    pass
                
                # 5. Tell the kernel to DENY access
                # We send back a specific response structure
                response = struct.pack("iI", metadata.fd, FAN_DENY)
                os.write(fd, response)
                
                # Close the file descriptor the kernel created for the event
                os.close(metadata.fd)

    except KeyboardInterrupt:
        print("\nDisarming trap...")
    finally:
        os.close(fd)

if __name__ == "__main__":
    # Ensure this file exists before running!
    target = "/home/canarywatch/Desktop/Passwords.txt"
    start_trap(target)