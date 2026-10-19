#!/usr/bin/env python3
"""Replace only the ARM64 VLC core in the pinned upstream LibVLC AAR."""
import argparse
import hashlib
from pathlib import Path
import zipfile

UPSTREAM_SHA256 = "b48dab96e0e90e34cce3861963500c144a5aadb1b249d501d6a4b104d849e61b"
ENTRY = "jni/arm64-v8a/libvlc.so"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--libvlc", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1]
                        / "android-libs/libvlc-all-3.7.7-netbios.aar")
    args = parser.parse_args()
    if hashlib.sha256(args.upstream.read_bytes()).hexdigest() != UPSTREAM_SHA256:
        parser.error("Upstream AAR does not match the pinned LibVLC 3.7.7 archive")
    core = args.libvlc.read_bytes()
    if core[:6] != b"\x7fELF\x02\x01" or core[18:20] != b"\xb7\x00":
        parser.error("Expected a little-endian ARM64 ELF library")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.upstream) as source:
        if source.namelist().count(ENTRY) != 1:
            parser.error("Upstream archive must contain exactly one ARM64 VLC core")
        with zipfile.ZipFile(args.output, "w") as target:
            for info in source.infolist():
                target.writestr(info, core if info.filename == ENTRY else source.read(info))
    print(f"Created {args.output}")
    print(f"ARM64 core SHA-256: {hashlib.sha256(core).hexdigest()}")


if __name__ == "__main__":
    main()
