# pwninit.py

A tool for intialization of ctf pwn challenges inspired by https://github.com/io12/pwninit.

## Features

* Downloads the correct interpreter to run the binary.
* Downloads other standard glibc libraries required by the binary, like `libpthread` or `libm` for example.
* Downloads debug symbols and unstrips all libraries, including `libc.so.*`, `ld-linux.so.*`, and other libraries.
* Patches the binary to use the correct interpreter and libraries, either manually or with `patchelf`.
* Writes a solve script to the current directory from a selection of customizable templates.
* Script that fetches glibc source code for better debugging.

## Install dependencies

```bash
./install_dependencies.sh
pip install -r requirements.txt
```

## Usage

### `pwninit.py`

Run `pwninit.py` inside the folder containing the binary (and libraries if they are provided), and it will automatically find the binary and libraries.
You can also specify the binary, libc or interpreter using `-b/--bin`, `--libc` and `--ld`.

### `pwnsrc.py`

This is an additional script which uses the `libc` to download glibc source code files.
This is useful in combination with debug symbols and a debugger like `gdb` which can list the source code relevant to the current point in the program's execution, and is very helpful in cases where you need to debug the inner workings of certain parts of glibc, such as `malloc`, `printf`, `dl-runtime` and more.

![](assets/gdb_malloc_example.png)

Running `pwnsrc.py` the first time will download a `.tar.xz` archive containing the glibc source code, using the libc to get the correct version.
Like `pwninit.py`, `pwnsrc.py` will automatically find the libc, and it can also be specified with `--libc`.

Once the archive has been downloaded, you can start extracting files from it, either manually or by using `--files`.
Any number of files can be specified with `--files`, and it can be the basename (e.g. `malloc.c`) or the full path (e.g. `glibc-2.31/malloc/malloc.c`).

`pwnsrc.py` will automatically find the archive if it exists, or it can be specified with `-s/--source`.

### Custom `solve.py` templates

You can specify which template to use using `-t/--template`.
There are two templates provided by default, but you can change these by adding files or editing files in the `templates` folder, the path of which is also provided when you run `-h/--help`.
The string `{bindings}` in the templates is used to substitute in the `ELF("<binary>")` initializations for the binary, libc and interpreter.

### `config.py`

This file contains some configuration options that can be changed by editing the file.
The options include:
* Names of `binary`, `libc`, `ld` in the `solve.py` template.
* Default `solve.py` template.
* Whether to use `patchelf` by default.

The path of this file is provided when you run `-h/--help`.
