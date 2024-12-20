#!/usr/bin/python3
import os
import re
import shutil
import tempfile

from elftools.elf.elffile import ELFFile

import config
import deb
import elfutils
import log
import templates
import utils


class LibcVersion:
    def __init__(self, line, arch):
        # line is what comes after "GNU C Library " and is of the form:
        # ([PKGVERSION])? [stable/development] release version X.YZ.
        self.raw = line.strip()
        self.arch = arch

        self.pkgversion = None
        self.release = None
        self.version_string = None
        self.version = None     # tuple of numbers
        # split up pkgversion
        self.flavour = None
        self.pkgname = None

        match = re.match(r"(?:GNU C Library )?(?:\((.+?)\) )?([a-z]+) release version (\d+(?:\.\d+)+)", self.raw)
        if match is None:
            return
        # release = "stable", "development" or "release"
        self.release = match.group(2)
        # Ex. version_string = "2.27", version = (2,27)
        self.version_string = match.group(3)
        self.version = tuple(int(x) for x in self.version_string.split("."))
        # PKGVERSION
        if match.group(1):
            self.pkgversion = match.group(1)
            words = self.pkgversion.split()
            if words[-1].startswith(self.version_string):
                self.pkgname = words.pop(-1)
            self.flavour = " ".join(words)

    @property
    def is_custom(self):
        # default pkgversion is "GNU libc" when compiling
        return self.pkgversion == "GNU libc"

    @property
    def is_stable(self):
        return self.release in ("stable", "release")

    @property
    def os(self):
        if self.pkgversion is None:
            return None
        os = self.pkgversion.split()[0]
        if os in ("Ubuntu", "Debian", "GNU"):
            return os
        return None

    @property
    def is_glibc(self):
        return "GLIBC" in self.flavour

    @property
    def is_eglibc(self):
        return "EGLIBC" in self.flavour

    @property
    def glibc_type(self):
        if self.is_glibc:
            return "GLIBC"
        if self.is_eglibc:
            return "EGLIBC"
        return None

    @property
    def libc_debname(self):
        if self.pkgname and self.arch:
            return f"libc6_{self.pkgname}_{self.arch}.deb"
        return None

    @property
    def libc_dbg_debname(self):
        if self.pkgname and self.arch:
            return f"libc6-dbg_{self.pkgname}_{self.arch}.deb"
        return None

    @property
    def libc_src_debname(self):
        if self.pkgname:
            return f"glibc-source_{self.pkgname}_all.deb"
        return None

    @property
    def base_pkgurl(self):
        if self.os == "Ubuntu":
            # works for both glibc and eglibc
            return "https://launchpad.net/ubuntu/+archive/primary/+files/"
        if self.os == "Debian":
            if self.is_glibc:
                return "https://deb.debian.org/debian/pool/main/g/glibc/"
        return None

    def _format_pkgurl(self, debname):
        base = self.base_pkgurl
        if base is None or debname is None:
            return None
        return base + debname

    @property
    def libc_pkgurl(self):
        return self._format_pkgurl(self.libc_debname)

    @property
    def libc_dbg_pkgurl(self):
        return self._format_pkgurl(self.libc_dbg_debname)

    @property
    def libc_src_pkgurl(self):
        return self._format_pkgurl(self.libc_src_debname)

    @property
    def arch_linux_gnu(self):
        return {
            "amd64": "x86_64-linux-gnu",
            "i386": "i386-linux-gnu",
        }.get(self.arch, None)

    @property
    def can_fetch_files(self):
        return bool(self.pkgname)

    def get_libc6_pkg_paths(self, name):
        return [
            os.path.join(f"./lib/{self.arch_linux_gnu}/", name),
            # seems to be used in ubuntu glibc 2.39
            os.path.join(f"./usr/lib/{self.arch_linux_gnu}/", name),
        ]

    def __str__(self):
        return self.raw


# takes the form: libname.so.XXX, libname.so, libname-2.27.so, libname_2.27.so
# also accepts: libcXXX, ld-XXX, ld
def get_lib_name(lib):
    basename = os.path.basename(lib)
    # ld names are more complex than other libraries
    if basename.startswith("ld-") or basename == "ld":
        return "ld"
    # this is for greater compatibility with pwninit libc detection
    if basename.startswith("libc"):
        return "libc"
    match = re.match(r"(.+?)(?:[-_]\d+\.\d+)?\.so", basename)
    if not match:
        return None
    name = match.group(1)
    return name

def is_patched(file):
    if not config.PATCHED_BINARY_SUFFIX:
        return False
    return file.endswith(config.PATCHED_BINARY_SUFFIX)

def replace_link(old, new):
    return os.path.islink(old) and not os.path.islink(new)

def find_binaries(binary=None, libc=None, ld=None, folder=".", libraries=None):
    if libraries is None:
        libraries = {}
    if ld:
        libraries["ld"] = ld
    if libc:
        libraries["libc"] = libc
    binary_provided = binary is not None
    for filename in os.listdir(folder):
        path = os.path.join(folder, filename)
        if not elfutils.is_elf(path):
            continue
        # check if file is a library
        lib_name = get_lib_name(filename)
        if lib_name is None:
            if binary_provided:
                continue
            # if the current binary:
            # * hasn't been found
            # * was already patched
            # * is a symlink
            # see if we can replace it
            if binary is None or is_patched(binary) or replace_link(binary, path):
                # ensure that this isn't a file we know about already
                # (samefile() returns true for a file and symlink to the file)
                for path2 in libraries.values():
                    if os.path.samefile(path, path2):
                        break
                else:
                    binary = path
            continue
        # if ld or libc were supplied, never overwrite them
        # or add any other libcs or lds
        # and by extension check for duplicates
        # since we know which one to use
        if lib_name == "ld" and ld is not None:
            continue
        elif lib_name == "libc" and libc is not None:
            continue
        # check duplicate
        path2 = libraries.get(lib_name, None)
        if path2:
            if replace_link(path2, path):
                # prioritise non-symlink files
                libraries[lib_name] = path
                path, path2 = path2, path
            log.warning(f"Duplicate libraries {path!r} and {path2!r}, defaulting to {path2!r}")
            continue
        libraries[lib_name] = path
    return binary, libraries


def fetch_missing_libraries(missing, libraries, version):
    missing_list = ', '.join(repr(m) for m in missing)
    if version is None:
        log.error(f"Can't fetch {missing_list} without knowing the libc version")
        return False
    if not version.can_fetch_files:
        log.error(f"Can't fetch {missing_list} as libc doesn't have a package name")
        return False
    dsts = []
    for i, needed_lib in enumerate(missing):
        name = os.path.basename(needed_lib)
        missing[i] = version.get_libc6_pkg_paths(name)
        dsts.append(name)
    url = version.libc_pkgurl
    print()
    dsts_list = ', '.join(repr(d) for d in dsts)
    log.info(f"Fetching {dsts_list} from {url}")
    successes = []
    with deb.DebPackage(url) as pkg:
        tar = pkg.tar
        if tar is None:
            log.error(f"Failed to fetch files: {pkg.error!r}")
            return False
        for files, dst in zip(missing, dsts):
            fsrc = None
            for file in files:
                name = os.path.basename(file)
                try:
                    fsrc = tar.extractfile(file)
                    break
                except KeyError:
                    pass
            else:
                log.error(f"Failed to fetch {dst!r}")
                continue

            with open(dst, "wb+") as fdst, fsrc:
                shutil.copyfileobj(fsrc, fdst)
            successes.append(dst)
            log.success(f"Successfully fetched {dst!r}")
    for lib in successes:
        libraries[get_lib_name(lib)] = lib
    return len(dsts) == len(successes)


def get_stripped_libraries(libraries):
    unstrip_libs = []
    for lib in libraries.values():
        with open(lib, "rb") as f:
            elf = ELFFile(f)
            if elf.get_dwarf_info().has_debug_info:
                continue
            out = elfutils.get_debug_link(elf)
            if out is None:
                log.error(f"Couldn't find .debug_link in {lib!r}, skipping")
                continue
            debug_link, crc32 = out
            unstrip_libs.append((lib, debug_link, crc32))
    return unstrip_libs


def unstrip_libraries(libraries, version):
    tempdir = tempfile.mkdtemp()
    debug_syms = {}
    url = version.libc_dbg_pkgurl
    log.info(f"Fetching debug symbols from {url}")
    with deb.DebPackage(url) as pkg:
        tar = pkg.tar
        if tar is None:
            log.error(f"Failed to fetch files: {pkg.error!r}")
            shutil.rmtree(tempdir)
            return False
        for name in tar.getnames():
            basename = os.path.basename(name)
            for lib, debug_link, crc32 in libraries:
                if debug_link != basename:
                    continue
                fileobj = tar.extractfile(name)
                if utils.crc32_fileobj(fileobj) != crc32:
                    continue
                fileobj.seek(0)
                debug_sym = os.path.join(tempdir, basename)
                with open(debug_sym, "wb+") as f, fileobj:
                    shutil.copyfileobj(fileobj, f)
                debug_syms[lib] = debug_sym
                break
    for lib, _, _ in libraries:
        debug_sym = debug_syms.get(lib, None)
        if debug_sym:
            # NOTE: it's also possible to keep the debug symbols separate
            # and in gdb change the directory where debug symbols are loaded from
            # if you wanted to keep the libraries unpatched
            # however unlike patchelf, it seems that the new sections added
            # aren't loaded into memory, and so don't affect how it's loaded
            _, stderr = utils.run_eu_unstrip(lib, debug_sym, output=lib)
            if not stderr:
                log.success(f"Successfully unstripped {lib!r}")
            else:
                log.error(f"Failed to unstrip {lib!r}: {stderr!r}")
        else:
            log.error(f"Failed to get debug symbols for {lib!r}")
    shutil.rmtree(tempdir)
    return True


def patch_binary(path, libraries, output=None, dont_patch=None):
    if dont_patch is None:
        dont_patch = set()
    patches = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        interp_patch = elfutils.get_interp_patch(elf)
        if interp_patch is not None:
            patches.append(interp_patch)
        patches += elfutils.get_needed_patches(elf)

    with open(path, "rb") as f:
        contents = bytearray(f.read())

    successful_patches = 0
    for needed, i in patches:
        if needed in dont_patch:
            log.warning(f"{needed!r} already fulfilled, skipping")
            continue
        lib_name = get_lib_name(needed)
        if lib_name is None or lib_name not in libraries:
            log.error(f"Couldn't find library for {needed!r}, skipping")
            continue
        symlink = "./" + lib_name
        if len(needed) < len(symlink):
            log.error(f"Patch {symlink!r} is longer than the existing needed library {needed!r}, skipping")
            continue
        patch = symlink.encode() + b"\x00"
        contents[i:i+len(patch)] = patch
        target = libraries[lib_name]
        if os.path.abspath(symlink) != os.path.abspath(target):
            log.info(f"Symlinking {symlink!r} -> {target!r}")
            try:
                os.symlink(target, symlink)
            except FileExistsError:
                log.warning(f"{symlink!r} already exists, skipping")
            except OSError as exception:
                log.error(f"Failed to make symlink: {exception!r}")
        successful_patches += 1
    # if no patches were made, no point creating a new binary
    if successful_patches == 0:
        log.warning(f"No patches were made, using original binary {path!r}")
        return path
    if output is None:
        output = path + config.PATCHED_BINARY_SUFFIX
    with open(output, "wb+") as f:
        f.write(bytes(contents))
    missing_patches = len(patches) - successful_patches
    if missing_patches == 0:
        log.success(f"Successfully wrote patched binary to {output!r}")
    else:
        word = "patch"
        if missing_patches > 1:
            word += "es"
        log.warning(f"Wrote patched binary to {output!r}, with {missing_patches} missing {word}")
    return output


def patch_binary_patchelf(path, libraries, output=None, dont_patch=None):
    if dont_patch is None:
        dont_patch = set()
    if output is None:
        output = path + config.PATCHED_BINARY_SUFFIX
    with open(path, "rb") as f:
        elf = ELFFile(f)
        needed = elfutils.get_needed(elf)
        requested_linker = elfutils.get_interp(elf)
    number_of_patches = len(needed)
    successful_patches = 0
    # if outputting to a different file, make a copy
    if not os.path.exists(output) or not os.path.samefile(path, output):
        shutil.copyfile(path, output)
    ld = libraries.get("ld", None)
    if ld:
        if requested_linker not in dont_patch:
            number_of_patches += 1
            ld = utils.basename_to_relpath(ld)
            _, stderr = utils.run_patchelf(output, ["--set-interpreter", ld])
            if stderr:
                log.error(f"Failed to patch interpreter: {stderr!r}")
            else:
                successful_patches += 1
        else:
            log.warning(f"{requested_linker!r} already fulfilled, skipping")
    for lib in needed:
        if lib in dont_patch:
            log.warning(f"{lib!r} already fulfilled, skipping")
            continue
        lib_name = get_lib_name(lib)
        if lib_name is None or lib_name not in libraries:
            log.error(f"Couldn't find library for {lib!r}, skipping")
            continue
        patch = utils.basename_to_relpath(libraries[lib_name])
        _, stderr = utils.run_patchelf(output, ["--replace-needed", lib, patch])
        if stderr:
            log.error(f"Failed to replace {lib!r} with {patch!r}: {stderr!r}")
        else:
            successful_patches += 1
    missing_patches = number_of_patches - successful_patches
    if successful_patches == 0:
        log.warning(f"No patches were made")
    elif missing_patches == 0:
        log.success(f"Successfully wrote patched binary to {output!r}")
    else:
        word = "patch"
        if missing_patches > 1:
            word += "es"
        log.warning(f"Wrote patched binary to {output!r}, with {missing_patches} missing {word}")
    return output


def write_solvepy(binary, libraries, template=None):
    if template is None:
        template = config.DEFAULT_TEMPLATE
    script = templates.get_template(template)
    if script is None:
        log.error("Failed to get template")
        return False
    bindings = []
    binary_name = config.TEMPLATE_BINARY_NAME
    bindings.append(f"{binary_name} = context.binary = ELF({binary!r})")
    # these may not exist if the binary is static
    libc = libraries.get("libc", None)
    ld = libraries.get("ld", None)
    if libc:
        libc_name = config.TEMPLATE_LIBC_NAME
        bindings.append(f"{libc_name} = ELF({libc!r}, checksec=False)")
    if ld:
        ld_name = config.TEMPLATE_LD_NAME
        bindings.append(f"{ld_name} = ELF({ld!r}, checksec=False)")
    with open("solve.py", "w+") as f:
        f.write(script.format(bindings="\n".join(bindings)))
    utils.chmod_x("solve.py")
    log.success("Successfully written solve.py")
    return True


def get_libc_version(libc, arch=None):
    try:
        f = open(libc, "rb")
    except OSError as exception:
        log.fatal(f"Can't open libc for reading: {exception!r}")

    with f:
        for line in f:
            parts = line.split(b"GNU C Library ", 1)
            if len(parts) == 2:
                version = LibcVersion(parts[1].decode(), arch)
                log.info(f"libc version: {version}")
                if version.is_custom:
                    # pkgname is None here as well
                    # but the reason for it here is custom compilation
                    log.warning("Libc appears to be custom-compiled")
                elif version.pkgname is None:
                    log.warning("Name of package not present in libc version string")
                return version
    log.error("Failed to find libc version")
    return None


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
    binary, libraries = find_binaries(binary=args.binary, libc=args.libc, ld=args.ld)
    if binary is None:
        log.fatal("No binary was supplied or found!")
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        arch = elfutils.get_arch(elf)
        if arch is None:
            log.fatal("Architecture not supported!")
        requested_linker = elfutils.get_interp(elf)
        needed = elfutils.get_needed(elf)
        dynamic = elfutils.get_dynamic(elf)
        log.info(f"bin: {binary} ({arch = })")
        if dynamic:
            runpath = elfutils.get_runpath_from_dynamic(dynamic)
            if runpath:
                log.info(f"RUNPATH: {runpath}")
            runpath_libs = {}
            for path in runpath:
                if not os.path.isdir(path):
                    continue
                find_binaries(binary=binary, folder=path, libraries=runpath_libs)
            dont_patch = set()
            for needed in elfutils.get_needed_from_dynamic(dynamic):
                if not utils.is_basename(needed) or get_lib_name(needed) in runpath_libs:
                    dont_patch.add(needed)
            # check if this exists?
            if not os.path.isabs(requested_linker):
                # normally an absolute path, so this means it's definitely patched
                dont_patch.add(requested_linker)
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
        version = get_libc_version(libc, arch=arch)

        missing = []
        for needed_lib in needed:
            lib_name = get_lib_name(needed_lib)
            if lib_name is None:
                continue
            if libraries.get(lib_name, None) is None:
                missing.append(needed_lib)

        ld = libraries.get("ld", None)
        if ld is None:
            missing.append(requested_linker)
        else:
            log.info(f"ld: {ld}")

        if missing:
            fetch_missing_libraries(missing, libraries, version)

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

        if do_unstrip and version and version.can_fetch_files:
            print()
            log.info("Finding stripped libraries to unstrip")
            unstrip_libs = get_stripped_libraries(libraries)
            if unstrip_libs:
                unstrip_libs_list = ', '.join(map(lambda x: repr(x[0]), unstrip_libs))
                log.info(f"Unstripping {unstrip_libs_list}")
                unstrip_libraries(unstrip_libs, version)
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
            binary = patch_binary_patchelf(binary, libraries, output=args.output, dont_patch=dont_patch)
        else:
            log.info("Patching binary manually")
            binary = patch_binary(binary, libraries, output=args.output, dont_patch=dont_patch)

    utils.chmod_x(binary)
    if do_solvepy:
        print()
        log.info("Writing solve.py")
        try:
            open("solve.py", "r").close()
            log.warning("solve.py already exists")
        except OSError:
            write_solvepy(binary, libraries, template=args.template)
