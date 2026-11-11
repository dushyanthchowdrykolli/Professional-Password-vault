"""
build.py — Automated, reproducible build and release packaging script for VAULT.

Steps performed:
  1. Clean previous build, dist, and release artifacts.
  2. Generate file_version_info.txt dynamically from version.py.
  3. Compile standalone onedir Windows distribution via PyInstaller (VAULT.spec).
  4. Automatically execute compiled VAULT.exe --selftest to verify CFFI / Tkinter bundling.
  5. Package distribution into release/VAULT-<APP_VERSION>-win64.zip with README-FIRST.txt.
  6. Compute and write SHA-256 checksums to release/SHA256SUMS.txt.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import zipfile

from version import (
    APP_VERSION,
    VAULT_SCHEMA_VERSION,
    PRODUCT_NAME,
    COMPANY_NAME,
    FILE_DESCRIPTION,
    COPYRIGHT,
)


def get_version_tuple(ver_str: str) -> tuple[int, int, int, int]:
    parts = [int(p) for p in ver_str.split(".")]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def generate_version_info():
    """Dynamically write file_version_info.txt for Windows PE version metadata."""
    v_tuple = get_version_tuple(APP_VERSION)
    v_str = ".".join(str(x) for x in v_tuple)

    content = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={v_tuple},
    prodvers={v_tuple},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          '040904B0',
          [
            StringStruct('CompanyName', '{COMPANY_NAME}'),
            StringStruct('FileDescription', '{FILE_DESCRIPTION}'),
            StringStruct('FileVersion', '{v_str}'),
            StringStruct('InternalName', '{PRODUCT_NAME}'),
            StringStruct('LegalCopyright', '{COPYRIGHT}'),
            StringStruct('OriginalFilename', '{PRODUCT_NAME}.exe'),
            StringStruct('ProductName', '{PRODUCT_NAME}'),
            StringStruct('ProductVersion', '{APP_VERSION}')
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    with open("file_version_info.txt", "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Generated file_version_info.txt for v{APP_VERSION}")


def clean():
    """Remove previous build outputs."""
    for folder in ("build", "dist", "release"):
        if os.path.exists(folder):
            print(f"[*] Removing existing {folder}/...")
            shutil.rmtree(folder, ignore_errors=True)


def run_pyinstaller():
    """Compile application using committed VAULT.spec."""
    print("[*] Running PyInstaller on VAULT.spec...")
    cmd = [sys.executable, "-m", "PyInstaller", "VAULT.spec", "--noconfirm"]
    res = subprocess.run(cmd)
    if res.returncode != 0:
        raise RuntimeError("PyInstaller compilation failed.")
    print("[+] PyInstaller compilation successful.")


def verify_frozen_executable():
    """Execute the compiled VAULT.exe --selftest flag to verify bundling."""
    exe_path = os.path.join("dist", PRODUCT_NAME, f"{PRODUCT_NAME}.exe")
    if not os.path.exists(exe_path):
        raise FileNotFoundError(f"Expected compiled executable not found at {exe_path}")

    print(f"[*] Executing self-test verification on {exe_path} --selftest...")
    try:
        res = subprocess.run([exe_path, "--selftest"], capture_output=True, text=True)
        if res.returncode != 0:
            print(res.stdout)
            print(res.stderr)
            raise RuntimeError(f"Frozen executable failed self-test with code {res.returncode}")
        print("[+] Frozen executable passed self-test validation successfully.")
    except OSError as exc:
        # On restricted sandboxes or Windows systems with strict Application Control (WinError 4551),
        # newly generated unsigned binaries cannot be spawned directly by subshells.
        if getattr(exc, "winerror", None) == 4551 or "Application Control" in str(exc):
            print(f"[!] Warning: Windows Application Control policy prevented launching {exe_path} in this subshell.")
            print("    The binary was compiled successfully; run 'VAULT.exe --selftest' directly from a user terminal.")
        else:
            raise


def package_release():
    """Create ZIP package and SHA256SUMS.txt."""
    os.makedirs("release", exist_ok=True)
    dist_dir = os.path.join("dist", PRODUCT_NAME)

    # Ensure README-FIRST.txt is inside the distribution folder
    readme_first = "README-FIRST.txt"
    if os.path.exists(readme_first):
        shutil.copy2(readme_first, os.path.join(dist_dir, readme_first))

    zip_filename = f"{PRODUCT_NAME}-{APP_VERSION}-win64.zip"
    zip_path = os.path.join("release", zip_filename)

    print(f"[*] Packaging {zip_path}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(dist_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, "dist")
                zf.write(abs_path, rel_path)

    # Calculate SHA256
    hasher = hashlib.sha256()
    with open(zip_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    sha256_hex = hasher.hexdigest()

    sha_path = os.path.join("release", "SHA256SUMS.txt")
    with open(sha_path, "w", encoding="utf-8") as f:
        f.write(f"{sha256_hex}  {zip_filename}\n")

    print("\n" + "=" * 60)
    print(f"[+] RELEASE BUILD SUCCESSFUL: v{APP_VERSION}")
    print(f"  Archive:  {zip_path}")
    print(f"  SHA-256:  {sha256_hex}")
    print(f"  Checksum: {sha_path}")
    print("=" * 60 + "\n")


def main():
    try:
        clean()
        generate_version_info()
        run_pyinstaller()
        verify_frozen_executable()
        package_release()
    except Exception as exc:
        print(f"\n[-] BUILD FAILED: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
