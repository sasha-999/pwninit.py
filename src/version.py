import os
import re

# ([PKGVERSION])? [stable/release/development] release version X.YZ ...
re_libc_version = r"(?:GNU C Library )?(?:\((.+?)\) )?([a-z]+) release version (\d+(?:\.\d+)+)"

class LibcVersion:
    def __init__(self, version=None, pkgversion=None, release=None, arch=None):
        if isinstance(version, (list, tuple)):
            self.version = tuple(version)
            self.version_string = ".".join(map(str, self.version))
        else:
            self.version_string = str(version)
            self.version = tuple(int(x) for x in self.version_string.split("."))

        self.pkgversion = pkgversion
        self.release = release
        self.arch = arch

        # split up pkgversion
        self.flavour = None
        self.pkgname = None
        if self.pkgversion:
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
    def is_eglibc(self):
        return "EGLIBC" in self.flavour

    @property
    def is_glibc(self):
        return "GLIBC" in self.flavour and not self.is_eglibc

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
        # TODO: add support for debug symbols of multiarch libcs of this form
        # for multiarch ones:
        # e.g. libc6-i386-dbgsym_2.35-0ubuntu3.10_amd64.ddeb
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
            # TODO: unstable releases
            # https://deb.sipwise.com/debian/pool/main/g/glibc/
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
            "arm64": "aarch64-linux-gnu",
            "armel": "arm-linux-gnueabi",
            "armhf": "arm-linux-gnueabihf",
            "mipsel": "mipsel-linux-gnu",
            "mips64el": "mips64el-linux-gnuabi64",
            "pp64el": "powerpc64le-linux-gnu",
            "s390x": "s390x-linux-gnu",
        }.get(self.arch, None)

    def get_libc6_pkg_paths(self, name):
        return [
            os.path.join(f"./lib/{self.arch_linux_gnu}/", name),
            # seems to be used in ubuntu glibc 2.39
            os.path.join(f"./usr/lib/{self.arch_linux_gnu}/", name),
            # TODO: add support for multiarch libc of this form
            # os.path.join(f"./usr/lib{bits}/", name),  # for libc6-i386_amd64 (32) / libc6-amd64_i386 (64) packages
        ]
    
    @property
    def supported_architectures(self):
        if self.os == "Ubuntu":
            # supports libc6-armel_armhf not armel
            return ["amd64", "i386", "arm64", "armhf", "ppc64el", "riscv64", "s390x"]
        if self.os == "Debian":
            return ["amd64", "i386", "arm64", "armel", "armhf", "mipsel", "mips64el", "ppc64el", "riscv64", "s390x"]
        return []

def parse_libc_version(string, arch=None):
    m = re.match(re_libc_version, string.strip())
    if m is None:
        return LibcVersion(arch=arch)
    pkgversion = m.group(1)
    release = m.group(2)
    version_string = m.group(3)
    return LibcVersion(
        version=version_string,
        pkgversion=pkgversion,
        release=release,
        arch=arch
    )

def get_libc_version_string(libc):
    prefix = b"GNU C Library "
    with open(libc, "rb") as f:
        for line in f:
            parts = line.split(prefix, 1)
            if len(parts) == 2:
                return (prefix + parts[1]).decode().strip()
    return None