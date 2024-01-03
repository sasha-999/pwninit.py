#!/usr/bin/python3
import os
import shutil
import sys
import tarfile

import config
import deb
import log
import pwninit

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
        description=("Fetches an archive containing glibc source code using libc, "
            "and can extract the specified source code files.\n"
            f"The config.py file is located at {config.__file__}"))
    ap.add_argument("--libc", default=None,
        help="Path of libc")
    ap.add_argument("-s", "--source", default=None,
        help="Path of glibc source archive")
    ap.add_argument("-f", "--files", default=None, nargs="+",
        help="Names/full paths of source code files to fetch")

    args = ap.parse_args()
    source = args.source
    fetched_source = False
    if source is None:
        # only need to find libc
        if args.libc:
            libc = args.libc
        else:
            _, libraries = pwninit.find_binaries(libc=None, binary="", ld="")
            libc = libraries.get("libc", None)
        if libc is None:
            log.fatal("No libc was supplied or found!")
        log.info(f"libc: {libc}")
        # arch isn't necessary to fetch glibc-source, so this works on any arch
        version = pwninit.get_libc_version(libc)
        # seems to be the only one used?
        ext = "xz"
        full_ext = f".tar.{ext}"
        source = config.GLIBC_SOURCE_FORMAT.format(version=version.version_string, ext=full_ext)
        # if this file already exists, don't fetch it again
        if not os.path.exists(source):
            url = version.libc_src_pkgurl
            log.info(f"Fetching glibc source from {url}")
            with deb.DebPackage(url) as pkg:
                tar = pkg.tar
                if tar is None:
                    log.fatal(f"Failed to fetch files: {pkg.error!r}")
                src = f"./usr/src/glibc/glibc-{version.version_string}{full_ext}"
                try:
                    fsrc = tar.extractfile(src)
                except KeyError:
                    log.fatal(f"Failed to find {src!r}")
                with open(source, "wb+") as fdst, fsrc:
                    shutil.copyfileobj(fsrc, fdst)
                log.success(f"Successfully written glibc-source to {source!r}")
                fetched_source = True
    else:
        try:
            open(source, "rb").close()
        except OSError as exception:
            log.fatal(f"Can't open glibc-source file: {exception!r}")
    if not args.files:
        if not fetched_source:
            print()
            log.warning("No source code files provided to extract")
        sys.exit(0)
    file_to_members = {}
    files = args.files
    filenames = [os.path.basename(file) for file in files]
    if args.source is None:
        # separate the following logging from previous logging
        print()
    log.info(f"glibc source: {source}")
    for filename in filenames:
        if filenames.count(filename) > 1:
            log.fatal(f"Duplicate {filename!r} files provided!")
    log.info("Finding source code files")
    with tarfile.open(source, "r") as tar:
        for member in tar.getmembers():
            name = member.name
            basename = os.path.basename(name)
            for file, filename in zip(files, filenames):
                if filename != basename:
                    continue
                if filename != file:
                    # if os.path.basename() != file, then file has a folder
                    # check if it has the same folder as well
                    # use commonpath() to allow for "./"
                    common = os.path.commonpath([file, member.name])
                    if common != member.name:
                        continue
                members = file_to_members.get(file, None)
                if members is None:
                    members = file_to_members[file] = []
                # only append if not a duplicate
                # tar files can contain duplicates
                for member2 in members:
                    if member.name == member2.name:
                        break
                else:
                    members.append(member)
        for file, filename in zip(files, filenames):
            members = file_to_members.get(file, None)
            if members is None:
                log.error(f"{file!r} wasn't found")
                continue
            if len(members) > 1:
                locations = "\n".join(member.name for member in members)
                log.error(f"{file!r} has multiple locations\n{locations}")
                continue
            member = members[0]
            dst = filename
            if os.path.exists(dst):
                log.error(f"{dst!r} already exists")
                continue
            with tar.extractfile(member) as fsrc, open(dst, "wb+") as fdst:
                shutil.copyfileobj(fsrc, fdst)
            log.success(f"Successfully extracted {file!r}")
