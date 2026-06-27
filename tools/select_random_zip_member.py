import hashlib
import json
import pathlib
import random
import sys
import time
import zipfile


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: select_random_zip_member.py <zip> <password> <out_dir>", file=sys.stderr)
        return 2

    zip_path = pathlib.Path(sys.argv[1])
    password = sys.argv[2].encode()
    out_dir = pathlib.Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as archive:
        members = [
            item
            for item in archive.infolist()
            if not item.is_dir() and not item.filename.endswith("/")
        ]
        if not members:
            raise RuntimeError("zip archive contains no file members")
        chosen = random.SystemRandom().choice(members)
        raw_name = pathlib.PurePosixPath(chosen.filename).name or f"sample_{int(time.time())}"
        target = out_dir / raw_name
        base = target.stem
        suffix = target.suffix
        counter = 1
        while target.exists():
            target = out_dir / f"{base}_{counter}{suffix}"
            counter += 1
        target.write_bytes(archive.read(chosen, pwd=password))

    sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
    print(
        json.dumps(
            {
                "zip": str(zip_path),
                "member_count": len(members),
                "chosen_member": chosen.filename,
                "extracted_path": str(target),
                "size": target.stat().st_size,
                "sha256": sha256,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
