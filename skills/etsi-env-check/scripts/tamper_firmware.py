"""
ETSI 5.3-2 / 5.3-9 firmware integrity test -- blind tamper encrypted firmware
==============================================================================
Usage: python tamper_firmware.py <src_firmware_path> [out_dir]

Generates one tampered variant (head+mid+tail, 1 byte each flipped via XOR 0xFF).
Stream copy, no full-file RAM load.
"""
import os
import sys
import hashlib
import io

# Force UTF-8 for stdout to avoid GBK encoding errors on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tamper_stream(src_path, out_path, offsets_set, xor_val=0xFF):
    """Stream copy src -> dst, XOR bytes at target offsets. No full-file RAM load."""
    size = os.path.getsize(src_path)
    CHUNK = 1 << 20  # 1 MB
    modified = 0

    with open(src_path, "rb") as fin, open(out_path, "wb") as fout:
        offset = 0
        while offset < size:
            chunk = bytearray(fin.read(min(CHUNK, size - offset)))
            chunk_end = offset + len(chunk)

            for off in offsets_set:
                if offset <= off < chunk_end:
                    local_off = off - offset
                    orig = chunk[local_off]
                    chunk[local_off] ^= xor_val
                    print(f"  [offset {off:#012x}] {orig:#04x} -> {chunk[local_off]:#04x}")
                    modified += 1

            fout.write(chunk)
            offset += len(chunk)
            pct = offset * 100.0 / size
            print(f"\r  copying... {pct:.0f}%", end="", flush=True)

        print(f"\r  done. {modified} byte(s) modified.          ")

    return sha256_file(out_path)


def main():
    if len(sys.argv) < 2:
        print("Usage: python tamper_firmware.py <src_firmware_path> [out_dir]")
        print("  src_firmware_path : path to the firmware file to tamper")
        print("  out_dir           : output directory (default: <src_dir>/tampered/)")
        sys.exit(1)

    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f"ERROR: source file not found: {src}")
        sys.exit(1)

    if len(sys.argv) >= 3:
        out_dir = sys.argv[2]
    else:
        out_dir = os.path.join(os.path.dirname(src) or ".", "tampered")

    os.makedirs(out_dir, exist_ok=True)
    file_size = os.path.getsize(src)
    base_name = os.path.splitext(os.path.basename(src))[0]

    print(f"Source: {src}")
    print(f"Size:   {file_size:,} bytes ({file_size / 1024 / 1024:.1f} MB)")
    print(f"SHA256: {sha256_file(src)}")
    print(f"Output: {out_dir}")
    print()

    # Single variant: head + mid + tail, 1 byte each
    offsets = {0x0000, file_size // 2, file_size - 0x100}
    desc = f"head(0x0)+mid({file_size//2:#x})+tail({file_size-0x100:#x}), 1 byte each"

    out_name = f"{base_name}_tampered.dav"
    out_path = os.path.join(out_dir, out_name)

    print(f"[tamper] {desc}")
    sha = tamper_stream(src, out_path, offsets)
    print(f"  SHA256: {sha}")
    print()

    print(f"Tampered firmware: {out_path}")
    print("Ready for upload test.")


if __name__ == "__main__":
    main()
