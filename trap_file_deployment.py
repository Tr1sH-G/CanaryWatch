#!/usr/bin/env python3

import os

# List of directories where files will be created
directories = [
    "/home/canarywatch/Desktop",
    "/home/canarywatch/Documents",
    "/home/canarywatch/Pictures",
    "/var",
    "/bin",
    "/usr",
    "/sbin"
]

for dir_path in directories:
    os.makedirs(dir_path, exist_ok=True)

for dir_path in directories:
    file_path = os.path.join(dir_path, ".aa.pdf")
    try:
        with open(file_path, "wb") as f:
            f.seek(4095)  
            f.write(b"\0")  
        print(f"Created: {file_path} (size: 4096 bytes)")
    except OSError as e:
        print(f"Error creating {file_path}: {e}")
