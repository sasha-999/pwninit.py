import os
import re
import shutil
import tempfile

from elftools.elf.elffile import ELFFile

from . import config
from . import deb
from . import elfutils
from . import log
from . import templates
from . import utils
from . import version

# takes the form: libname.so.XXX, libname.so, libname-2.27.so, libname_2.27.so
# also accepts: libcXXX, ld-XXX, ld
def get_lib_name(lib, strict=False):
    basename = os.path.basename(lib)
    # ld names are more complex than other libraries
    if basename.startswith("ld-") or basename == "ld":
        return "ld"
    # this is for greater compatibility with pwninit libc detection
    if basename.startswith("libc") and not basename[4:5].isalpha():
        return "libc"
    match = re.match(r"(.+?)(?:[-_]\d+\.\d+)?\.so", basename)
    if not match:
        if strict:
            return None
        return basename
    name = match.group(1)
    #if strict and not name.startswith("lib"):
    #    return None
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
        lib_name = get_lib_name(filename, strict=True)
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


def fetch_missing_libraries(missing, libraries, libc):
    missing_list = ', '.join(repr(m) for m in missing)
    if libc is None:
        log.error(f"Can't fetch {missing_list} without knowing the libc version")
        return False
    if libc.arch not in libc.supported_architectures:
        log.error(f"Architecture {libc.arch!r} not supported by {libc.os!r}")
        return False
    if not libc.pkgname:
        log.error(f"Can't fetch {missing_list} as libc doesn't have a package name")
        return False
    dsts = []
    for i, needed_lib in enumerate(missing):
        name = os.path.basename(needed_lib)
        missing[i] = libc.get_libc6_pkg_paths(name)
        dsts.append(name)
    url = libc.get_libc_pkgurl()
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


def unstrip_libraries(libraries, libc):
    tempdir = tempfile.mkdtemp()
    debug_syms = {}
    url = libc.get_libc_dbg_pkgurl()
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
        if lib_name not in libraries:
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
        if lib_name not in libraries:
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
    string = None
    try:
        string = version.get_libc_version_string(libc)
    except OSError as exception:
        log.error(f"Error reading libc file {libc!r}: {exception!r}")

    if string:
        libc = version.parse_libc_version(string, arch=arch)
        log.info(f"libc version: {string!r}")
        if libc.is_custom:
            # pkgname is None here as well
            # but the reason for it here is custom compilation
            log.warning("Libc appears to be custom-compiled")
        elif libc.pkgname is None:
            log.warning("Name of package not present in libc version string")
        return libc

    log.error("Failed to find libc version")
    return None