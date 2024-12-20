import os
import subprocess
import zlib


def run_command(cmd, args, cwd=None):
    args = [cmd] + args
    try:
        proc = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    except Exception as exception:
        return "", str(exception)
    return proc.stdout, proc.stderr

def run_patchelf(path, args):
    return run_command("patchelf", [path] + args)

def run_eu_unstrip(stripped, debug, output=None):
    args = [stripped, debug]
    if output:
        args += ["-o", output]
    return run_command("eu-unstrip", args)

def run_ar(args, cwd=None):
    return run_command("ar", args, cwd=cwd)

def chmod_x(path):
    return run_command("chmod", ["+x", path])

def is_basename(path):
    return os.path.basename(path) == path

def basename_to_relpath(name):
    if is_basename(name):
        return os.path.join(".", name)
    return name

def crc32_fileobj(fileobj, chunksize=0x10000):
    hash = 0
    while True:
        chunk = fileobj.read(chunksize)
        if not chunk:
            return hash
        hash = zlib.crc32(chunk, hash)
