#!/usr/bin/env python3
"""
VTToolz multi-platform build helper.

Build standalone binaries or OS packages for common targets.

Usage:
    python build.py --target win64
    python build.py --target win32
    python build.py --target linux
    python build.py --target macos
    python build.py --target debian
    python build.py --target redhat
    python build.py --target bsd
    python build.py --target all
    python build.py --list-targets
    python build.py --target win64 --clean --onefile

Notes:
  - win32 / win64 / linux / macos use PyInstaller (must run on matching OS
    or a compatible CI runner; pure cross-compile of Python exe is limited).
  - debian / redhat produce source layout + packaging hints (or .deb/.rpm
    when native tools are available).
  - bsd prepares a FreeBSD-oriented layout.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
ENTRY = ROOT / "run_vttoolz.py"
PKG_NAME = "vttoolz"

# ---------------------------------------------------------------------------
# Target definitions
# ---------------------------------------------------------------------------

TARGETS = {
    "win32": {
        "os": "windows",
        "arch": "x86",
        "pyinstaller_args": ["--onefile", "--console"],
        "ext": ".exe",
        "desc": "Windows 32-bit (x86) executable via PyInstaller",
    },
    "win64": {
        "os": "windows",
        "arch": "x86_64",
        "pyinstaller_args": ["--onefile", "--console"],
        "ext": ".exe",
        "desc": "Windows 64-bit (x86_64) executable via PyInstaller",
    },
    "linux": {
        "os": "linux",
        "arch": "x86_64",
        "pyinstaller_args": ["--onefile", "--console"],
        "ext": "",
        "desc": "Generic Linux x86_64 binary via PyInstaller",
    },
    "linux-arm64": {
        "os": "linux",
        "arch": "aarch64",
        "pyinstaller_args": ["--onefile", "--console"],
        "ext": "",
        "desc": "Linux ARM64 binary via PyInstaller",
    },
    "macos": {
        "os": "darwin",
        "arch": "x86_64",
        "pyinstaller_args": ["--onefile", "--console"],
        "ext": "",
        "desc": "macOS Intel binary via PyInstaller",
    },
    "macos-arm64": {
        "os": "darwin",
        "arch": "arm64",
        "pyinstaller_args": ["--onefile", "--console"],
        "ext": "",
        "desc": "macOS Apple Silicon (arm64) binary via PyInstaller",
    },
    "debian": {
        "os": "linux",
        "arch": "any",
        "kind": "deb",
        "desc": "Debian/Ubuntu package layout (.deb when dpkg-deb is available)",
    },
    "redhat": {
        "os": "linux",
        "arch": "any",
        "kind": "rpm",
        "desc": "RHEL/Fedora/CentOS package layout (.rpm when rpmbuild is available)",
    },
    "bsd": {
        "os": "freebsd",
        "arch": "any",
        "kind": "bsd",
        "desc": "FreeBSD / OpenBSD oriented install layout",
    },
    "wheel": {
        "os": "any",
        "arch": "any",
        "kind": "wheel",
        "desc": "Pure Python wheel (pip install)",
    },
    "sdist": {
        "os": "any",
        "arch": "any",
        "kind": "sdist",
        "desc": "Source distribution tarball",
    },
}


def host_info() -> dict[str, str]:
    system = platform.system().lower()  # windows, linux, darwin
    machine = platform.machine().lower()
    return {"system": system, "machine": machine, "python": sys.version.split()[0]}


def log(msg: str) -> None:
    print(msg)


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        log("[*] Installing PyInstaller…")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller", "-q"])


def clean_artifacts() -> None:
    for d in (DIST, BUILD):
        if d.exists():
            log(f"[*] Removing {d}")
            shutil.rmtree(d, ignore_errors=True)
    for spec in ROOT.glob("*.spec"):
        spec.unlink(missing_ok=True)
        log(f"[*] Removed {spec.name}")


def check_host_compatible(target: str) -> bool:
    """Warn when building a native binary on a mismatched host."""
    meta = TARGETS[target]
    if meta.get("kind"):
        return True  # packaging targets are more flexible

    host = host_info()
    want_os = meta["os"]
    system = host["system"]

    mapping = {"windows": "windows", "linux": "linux", "darwin": "darwin"}
    if mapping.get(want_os) != system:
        log(
            f"[!] Warning: target '{target}' expects OS '{want_os}', "
            f"but host is '{system}'. PyInstaller cannot truly cross-compile. "
            f"Use CI (GitHub Actions) on the matching runner."
        )
        return False
    return True


def build_pyinstaller(target: str, onefile: bool = True, windowed: bool = False) -> Path:
    ensure_pyinstaller()
    meta = TARGETS[target]
    check_host_compatible(target)

    if not ENTRY.exists():
        raise FileNotFoundError(f"Entry script missing: {ENTRY}")

    name = f"{PKG_NAME}-{target}"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        name,
        "--noconfirm",
        "--clean",
    ]
    cmd.append("--onefile" if onefile else "--onedir")
    cmd.append("--windowed" if windowed else "--console")

    for pkg in ("vttoolz", "requests", "certifi", "charset_normalizer", "idna", "urllib3"):
        cmd.extend(["--collect-all", pkg])

    for mod in (
        "vttoolz",
        "vttoolz.cli",
        "vttoolz.client",
        "vttoolz.report",
        "vttoolz.utils",
        "vttoolz.anti_abuse",
        "vttoolz.captcha",
        "requests",
        "urllib3",
        "certifi",
        "charset_normalizer",
        "idna",
    ):
        cmd.extend(["--hidden-import", mod])

    ico = ROOT / "vttoolz.ico"
    if ico.exists() and meta["os"] == "windows":
        cmd.extend(["--icon", str(ico)])

    cmd.append(str(ENTRY))
    log(f"[*] Building target={target} …")
    subprocess.check_call(cmd, cwd=ROOT)

    ext = meta.get("ext", "")
    built = DIST / f"{name}{ext}"
    if not built.exists():
        # onedir fallback
        built = DIST / name
    log(f"[+] Output: {built}")
    return built


def build_wheel() -> None:
    log("[*] Building wheel + sdist …")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "build", "-q"])
    subprocess.check_call([sys.executable, "-m", "build"], cwd=ROOT)
    log(f"[+] Packages in {DIST}/")


def build_debian() -> Path:
    """Create a simple Debian package structure and optionally .deb."""
    version = "0.3.1"
    arch = "all"
    pkg_dir = BUILD / f"{PKG_NAME}_{version}_{arch}"
    if pkg_dir.exists():
        shutil.rmtree(pkg_dir)

    deb_root = pkg_dir
    bin_dir = deb_root / "usr" / "local" / "bin"
    lib_dir = deb_root / "usr" / "local" / "lib" / PKG_NAME
    control_dir = deb_root / "DEBIAN"
    for d in (bin_dir, lib_dir, control_dir):
        d.mkdir(parents=True)

    # copy package sources
    src = ROOT / "vttoolz"
    dest = lib_dir / "vttoolz"
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(ROOT / "run_vttoolz.py", lib_dir / "run_vttoolz.py")

    launcher = bin_dir / PKG_NAME
    launcher.write_text(
        f"#!/usr/bin/env python3\n"
        f"import sys\n"
        f"sys.path.insert(0, '/usr/local/lib/{PKG_NAME}')\n"
        f"from vttoolz.cli import main\n"
        f"sys.exit(main())\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)

    control = control_dir / "control"
    control.write_text(
        f"Package: {PKG_NAME}\n"
        f"Version: {version}\n"
        f"Section: utils\n"
        f"Priority: optional\n"
        f"Architecture: {arch}\n"
        f"Depends: python3 (>= 3.9), python3-requests\n"
        f"Maintainer: VTToolz Contributors\n"
        f"Description: VirusTotal CLI without official API\n"
        f" Hash lookup, detections, cookies and optional upload helpers.\n",
        encoding="utf-8",
    )

    DIST.mkdir(exist_ok=True)
    out_deb = DIST / f"{PKG_NAME}_{version}_{arch}.deb"

    if shutil.which("dpkg-deb"):
        subprocess.check_call(["dpkg-deb", "--build", str(deb_root), str(out_deb)])
        log(f"[+] Debian package: {out_deb}")
    else:
        archive = DIST / f"{PKG_NAME}_{version}_debian_tree"
        if archive.exists():
            shutil.rmtree(archive)
        shutil.copytree(deb_root, archive)
        log(f"[+] Debian tree (dpkg-deb not found): {archive}")
        log("    On Debian/Ubuntu run: dpkg-deb --build that_tree package.deb")
        return archive

    return out_deb


def build_redhat() -> Path:
    """Prepare RPM-oriented layout + spec snippet."""
    version = "0.3.1"
    rpm_root = BUILD / "rpm"
    if rpm_root.exists():
        shutil.rmtree(rpm_root)
    spec_dir = rpm_root / "SPECS"
    sources = rpm_root / "SOURCES"
    spec_dir.mkdir(parents=True)
    sources.mkdir(parents=True)

    # source tarball of the project (minimal)
    tarball = sources / f"{PKG_NAME}-{version}.tar.gz"
    subprocess.check_call(
        [
            "tar",
            "-czf",
            str(tarball),
            "--exclude=__pycache__",
            "--exclude=*.pyc",
            "--exclude=dist",
            "--exclude=build",
            "-C",
            str(ROOT),
            "vttoolz",
            "run_vttoolz.py",
            "pyproject.toml",
            "requirements.txt",
            "README.md",
        ]
    )

    spec = spec_dir / f"{PKG_NAME}.spec"
    spec.write_text(
        f"""Name:           {PKG_NAME}
Version:        {version}
Release:        1%{{?dist}}
Summary:        VirusTotal CLI without official API
License:        MIT
URL:            https://github.com/yourname/VTToolz
Source0:        %{{name}}-%{{version}}.tar.gz
BuildArch:      noarch
Requires:       python3 >= 3.9, python3-requests

%description
Hash lookup, detections, cookies bypass and optional upload for VirusTotal UI.

%prep
%setup -q -c

%install
mkdir -p %{{buildroot}}/usr/lib/%{{name}}
mkdir -p %{{buildroot}}/usr/bin
cp -r vttoolz run_vttoolz.py %{{buildroot}}/usr/lib/%{{name}}/
cat > %{{buildroot}}/usr/bin/%{{name}} << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/usr/lib/{PKG_NAME}')
from vttoolz.cli import main
sys.exit(main())
EOF
chmod 755 %{{buildroot}}/usr/bin/%{{name}}

%files
/usr/bin/%{{name}}
/usr/lib/%{{name}}

%changelog
* Sat Oct 17 2026 VTToolz Contributors - {version}-1
- Initial package
""",
        encoding="utf-8",
    )

    DIST.mkdir(exist_ok=True)
    out = DIST / f"{PKG_NAME}-{version}-redhat"
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(rpm_root, out)
    log(f"[+] RPM layout: {out}")
    if shutil.which("rpmbuild"):
        log("    Run: rpmbuild -ba SPECS/vttoolz.spec  (from that tree)")
    else:
        log("    rpmbuild not found – layout only.")
    return out


def build_bsd() -> Path:
    """FreeBSD-style install prefix layout."""
    version = "0.3.1"
    prefix = BUILD / f"{PKG_NAME}-bsd-{version}"
    if prefix.exists():
        shutil.rmtree(prefix)
    bindir = prefix / "bin"
    libdir = prefix / "lib" / PKG_NAME
    bindir.mkdir(parents=True)
    libdir.mkdir(parents=True)

    shutil.copytree(
        ROOT / "vttoolz",
        libdir / "vttoolz",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copy2(ROOT / "run_vttoolz.py", libdir / "run_vttoolz.py")

    script = bindir / PKG_NAME
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.path.insert(0, '{libdir}')\n"
        "from vttoolz.cli import main\n"
        "sys.exit(main())\n",
        encoding="utf-8",
    )
    script.chmod(0o755)

    readme = prefix / "README.BSD"
    readme.write_text(
        f"VTToolz {version} – BSD layout\n\n"
        "Install:\n"
        "  sudo cp -R bin/* /usr/local/bin/\n"
        "  sudo cp -R lib/* /usr/local/lib/\n"
        "  sudo pkg install py39-requests   # or equivalent\n",
        encoding="utf-8",
    )

    DIST.mkdir(exist_ok=True)
    out = DIST / f"{PKG_NAME}-{version}-bsd"
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(prefix, out)
    log(f"[+] BSD layout: {out}")
    return out


def list_targets() -> None:
    print("Available --target values:\n")
    for name, meta in TARGETS.items():
        print(f"  {name:<14} {meta['desc']}")
    print("\n  all             Build every target that this host can reasonably attempt")
    host = host_info()
    print(f"\nHost: system={host['system']} machine={host['machine']} python={host['python']}")


def build_target(target: str, onefile: bool, windowed: bool) -> None:
    if target not in TARGETS:
        raise SystemExit(f"Unknown target: {target}. Use --list-targets.")

    meta = TARGETS[target]
    kind = meta.get("kind")

    if kind == "wheel" or kind == "sdist":
        build_wheel()
    elif kind == "deb":
        build_debian()
    elif kind == "rpm":
        build_redhat()
    elif kind == "bsd":
        build_bsd()
    else:
        build_pyinstaller(target, onefile=onefile, windowed=windowed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VTToolz multi-platform build tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python build.py --list-targets
  python build.py --target win64 --clean
  python build.py --target linux
  python build.py --target debian
  python build.py --target redhat
  python build.py --target bsd
  python build.py --target wheel
  python build.py --target all --clean
        """,
    )
    parser.add_argument(
        "--target",
        "-t",
        metavar="NAME",
        help="Build target (win32, win64, linux, macos, debian, redhat, bsd, wheel, …)",
    )
    parser.add_argument("--list-targets", action="store_true", help="List all targets and exit")
    parser.add_argument("--clean", action="store_true", help="Remove previous build/dist artifacts first")
    parser.add_argument("--onefile", action="store_true", default=True, help="PyInstaller one-file mode (default)")
    parser.add_argument("--onedir", action="store_true", help="PyInstaller one-dir mode")
    parser.add_argument("--windowed", action="store_true", help="No console window (Windows GUI subsystem)")

    args = parser.parse_args(argv)

    if args.list_targets or not args.target:
        list_targets()
        if not args.target:
            return 0

    if args.clean:
        clean_artifacts()

    onefile = not args.onedir
    targets = list(TARGETS.keys()) if args.target == "all" else [args.target]

    failed = []
    for t in targets:
        try:
            log(f"\n=== Target: {t} ===")
            build_target(t, onefile=onefile, windowed=args.windowed)
        except Exception as exc:
            log(f"[!] Failed ({t}): {exc}")
            failed.append(t)

    if failed:
        log(f"\n[!] Failed targets: {', '.join(failed)}")
        return 1

    log("\n[+] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())