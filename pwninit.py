#!/usr/bin/python3
import os
import shutil

from elftools.elf.elffile import ELFFile

from src import config
from src import core
from src import elfutils
from src import log
from src import templates
from src import utils


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
        description=("Automates the initialization of a pwn challenge.\n"
            f"The config.py file is located at {config.__file__}"))
    ap.add_argument("-b", "--bin", default=None, dest="binary",
        help="Path of binary to patch")
    ap.add_argument("--libc", default=None, dest="libc",
        help="Path of libc")
    ap.add_argument("--ld", default=None, dest="ld",
        help="Path of interpreter")
    ap.add_argument("-nu", "--no-unstrip", default=False, action="store_true",
        help="Disable unstripping of libraries (ignored if binary is static)")
    ap.add_argument("-np", "--no-patch", default=False, action="store_true",
        help="Disable patching of binary (ignored if binary is static)")
    ap.add_argument("-ns", "--no-solvepy", default=False, action="store_true",
        help="Disable writing solve.py")
    ap.add_argument("--use-patchelf", default=config.USE_PATCHELF,
        action="store_true",
        help="Use patchelf for patching the binary")
    ap.add_argument("-l", "--libs", default=None, dest="libs",
        help="Path of folder to store libraries in (ignored if binary is static)")
    ap.add_argument("-t", "--template", default=config.DEFAULT_TEMPLATE,
        dest="template", choices=templates.get_available_templates(),
        help=("Template of solve script. "
            f"Templates are stored in {templates.get_templates_folder()}"))
    ap.add_argument("-o", "--output", default=None, dest="output",
        help=("Place patched binary into OUTPUT "
            f"(defaults to BINARY{config.PATCHED_BINARY_SUFFIX})"))

    args = ap.parse_args()
    do_unstrip = not args.no_unstrip
    do_patch = not args.no_patch
    do_solvepy = not args.no_solvepy
    binary, libraries = core.find_binaries(binary=args.binary, libc=args.libc, ld=args.ld)
    if binary is None:
        log.fatal("No binary was supplied or found!")
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        arch = elfutils.get_arch(elf)
        requested_linker = elfutils.get_interp(elf)
        dynamic = elfutils.get_dynamic(elf)
        log.info(f"bin: {binary} ({arch = })")
        if dynamic:
            needed = elfutils.get_needed_from_dynamic(dynamic)
            runpath = elfutils.get_runpath_from_dynamic(dynamic)
            if runpath:
                log.info(f"RUNPATH: {runpath}")
            runpath_libs = {}
            for path in runpath:
                if not os.path.isdir(path):
                    continue
                core.find_binaries(binary=binary, folder=path, libraries=runpath_libs)
            dont_patch = set()
            for needed_lib in needed:
                lib_name = core.get_lib_name(needed_lib)
                if not utils.is_basename(needed_lib) and elfutils.is_elf(needed_lib):
                    dont_patch.add(needed_lib)
                    libraries[lib_name] = needed_lib
                if utils.is_basename(needed_lib) and lib_name in runpath_libs:
                    dont_patch.add(needed_lib)
            # check if this exists?
            if requested_linker and not os.path.isabs(requested_linker) and elfutils.is_elf(requested_linker):
                # normally an absolute path, so this means it's definitely patched
                dont_patch.add(requested_linker)
                libraries["ld"] = requested_linker
            #if not any(lambda x: requested_linker.startswith(x), ["/lib/", "/lib64/"]):
            #    dont_patch.add(requested_linker)
            libraries = runpath_libs | libraries

    if dynamic is None:
        libraries = {}
        do_patch = False
        log.warning("Binary is statically linked, not patching the binary")
    elif not libraries:
        do_patch = False
        log.warning("No libraries were found, not patching the binary")
    elif libraries.get("libc", None):
        libc = libraries["libc"]
        log.info(f"libc: {libc}")

        if arch == "arm":
            # if arch is "arm", use libc to decide between armel and armhf
            # this can be determined with e_flags
            try:
                f = open(libc, "rb")
                with f:
                    elf = ELFFile(f)
                    arch = elfutils.get_arch(elf)
            except OSError:
                # if libc can't be opened here, the error will be caught in core.get_libc_version()
                pass
        libc = core.get_libc_version(libc, arch=arch)

        missing = []
        for needed_lib in needed:
            lib_name = core.get_lib_name(needed_lib)
            if libraries.get(lib_name, None) is None:
                missing.append(needed_lib)

        ld = libraries.get("ld", None)
        if ld is None:
            if requested_linker:
                missing.append(requested_linker)
        else:
            log.info(f"ld: {ld}")

        if missing:
            core.fetch_missing_libraries(missing, libraries, libc)

        # it's possible that fetching the interpreter failed
        ld = libraries.get("ld", None)
        if ld is None:
            log.error("Interpreter not found")
        else:
            try:
                open(ld, "rb").close()
                utils.chmod_x(ld)
            except OSError as exception:
                log.error(f"Can't open {ld!r}: {exception!r}")

        if do_unstrip and libc and libc.pkgname and arch in libc.supported_architectures:
            print()
            log.info("Finding stripped libraries to unstrip")
            unstrip_libs = core.get_stripped_libraries(libraries)
            if unstrip_libs:
                unstrip_libs_list = ', '.join(map(lambda x: repr(x[0]), unstrip_libs))
                log.info(f"Unstripping {unstrip_libs_list}")
                core.unstrip_libraries(unstrip_libs, libc)
            else:
                log.warning("No libraries to unstrip")

        if args.libs:
            folder = args.libs
            exception = None
            print()
            log.info(f"Moving libraries to {folder!r}")
            try:
                os.mkdir(folder)
            except OSError as e:
                # don't print error here because it could error
                # due to the folder already existing
                exception = str(e)

            if os.path.isdir(folder):
                for name, lib in list(libraries.items()):
                    src = lib
                    dst = os.path.join(folder, os.path.basename(lib))
                    try:
                        shutil.move(src, dst)
                        libraries[name] = dst
                    except OSError as exception:
                        log.error(f"Failed to move {src} to {dst}: {str(exception)!r}")
            else:
                log.error(f"Failed to create folder {folder!r}: {exception!r}")

    if do_patch:
        print()
        if args.use_patchelf:
            log.info("Patching binary using patchelf")
            binary = core.patch_binary_patchelf(binary, libraries, output=args.output, dont_patch=dont_patch)
        else:
            log.info("Patching binary manually")
            binary = core.patch_binary(binary, libraries, output=args.output, dont_patch=dont_patch)

    utils.chmod_x(binary)
    if do_solvepy:
        print()
        log.info("Writing solve.py")
        try:
            open("solve.py", "r").close()
            log.warning("solve.py already exists")
        except OSError:
            core.write_solvepy(binary, libraries, template=args.template)
