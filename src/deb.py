import os
import shutil
import tarfile
import tempfile

import requests

from . import utils

def get_ubuntu_binary_url(name, pkgname, arch="all"):
    return f"https://launchpad.net/ubuntu/+archive/primary/+files/{name}_{pkgname}_{arch}.deb"

def get_debian_binary_url(name, pkgname, arch="all"):
    # debsnap -a ARCH NAME PKGNAME
    # e.g. debsnap -a amd64 libc6 2.41-12+deb13u2
    # e.g. debsnap -a all glibc-source 2.41-12+deb13u2

    baseurl = "https://snapshot.debian.org"
    r = requests.get(f"{baseurl}/mr/binary/{name}/")
    # versions are sorted from newest to oldest
    for version in r.json()["result"]:
        if version["binary_version"] == pkgname:
            break
    else:
        return None
    r = requests.get(f"{baseurl}/mr/package/{version['source']}/{version['version']}/binfiles/{version['name']}/{version['binary_version']}?fileinfo=1")
    for result in r.json()["result"]:
        if result["architecture"] == arch:
            return f"{baseurl}/file/{result['hash']}"
    return None


class DebPackage:
    def __init__(self, url):
        self.tar = None
        self.tempdir = None
        self.error = None
        # fetch deb
        debname = url.split("/")[-1]
        try:
            r = requests.get(url, stream=True)
        except Exception as exception:
            self.error = str(exception)
            return
        if r.status_code != 200:
            self.error = f"GET request returned {r.status_code}"
            return
        # copy deb to temp folder
        self.tempdir = tempfile.mkdtemp()
        debpath = os.path.join(self.tempdir, debname)
        with open(debpath, "wb+") as f:
            shutil.copyfileobj(r.raw, f)
        # extract data.tar from deb to the same folder
        self.tar = self._get_data_tar(debpath)

    def _extract_file_deb(self, deb, name, folder="."):
        # args = ["x", "--output", folder, deb, name] (binutils >= 2.34)
        _, stderr = utils.run_ar(["x", deb, name], cwd=folder)
        if not stderr:
            return os.path.join(folder, name)
        self.error = f"Failed to run 'ar x {deb} {name}': err={stderr}"
        return None

    def _get_data_tar(self, debpath):
        # find data.tar.{ext}
        out, stderr = utils.run_ar(["t", debpath])
        if stderr:
            self.error = f"Failed to run 'ar t {debpath}': err={stderr}"
            return None
        filenames = out.strip().splitlines()
        for tar_name in filenames:
            if tar_name.startswith("data.tar"):
                break
        else:
            self.error = "Failed to find data.tar"
            return None
        # extract data.tar.{ext}
        folder = self.tempdir
        tar_path = self._extract_file_deb(debpath, tar_name, folder=folder)
        if not tar_path:
            return None
        try:
            return tarfile.open(tar_path, "r:*")
        except tarfile.ReadError:
            # data.tar.{ext} exists, but can't be extracted with tarfile
            pass
        if tar_path.endswith(".zst"):
            # tarfile doesn't support .zst (before python 3.14)
            # do it ourselves with zstandard
            import zstandard
            dctx = zstandard.ZstdDecompressor()
            tar_zst_path = tar_path
            tar_path = os.path.join(folder, "data.tar")
            with open(tar_zst_path, "rb") as ifh, open(tar_path, "wb+") as ofh:
                dctx.copy_stream(ifh, ofh)
            return tarfile.open(tar_path, "r:")
        return None

    def close(self):
        if self.tar:
            self.tar.close()
            self.tar = None
        if self.tempdir:
            shutil.rmtree(self.tempdir)
            self.tempdir = None

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.close()
