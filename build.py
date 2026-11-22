#!/usr/bin/env python3
"""students.json + common.json -> data/<id>.bin (학생별 암호화 파일).

사용법:  python3 build.py
- students.json 에 code 가 없는 학생은 코드를 자동 발급해 students.json 에 저장한다.
- students.json 은 내 컴퓨터에만 둔다(.gitignore). 저장소에는 data/*.bin 만 올라간다.
"""
import hashlib
import json
import os
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # 헷갈리는 0 O 1 I 제외
CODE_LEN = 10
ITER = 200_000
ROOT = os.path.dirname(os.path.abspath(__file__))


def norm(code: str) -> str:
    """정규형: 대문자, XXXXX-XXXXX (웹페이지의 fetchData 와 동일해야 함)."""
    raw = "".join(code.split()).replace("-", "").upper()
    return raw[:5] + "-" + raw[5:]


def new_code() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LEN))
    return raw[:5] + "-" + raw[5:]


def file_id(code: str) -> str:
    return hashlib.sha256(("id:" + code).encode()).hexdigest()[:16]


def encrypt(code: str, payload: dict) -> bytes:
    salt, iv = os.urandom(16), os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", code.encode(), salt, ITER, dklen=32)
    ct = AESGCM(key).encrypt(iv, json.dumps(payload, ensure_ascii=False).encode(), None)
    return salt + iv + ct


def load(name: str, default):
    path = os.path.join(ROOT, name)
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    students = load("students.json", None)
    if students is None:
        print("students.json 이 없습니다. students.example.json 을 복사해 만드세요.")
        return 1
    common = load("common.json", {})

    out_dir = os.path.join(ROOT, "data")
    os.makedirs(out_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        if f.endswith(".bin"):
            os.remove(os.path.join(out_dir, f))

    changed = False
    seen = set()
    for s in students:
        if not s.get("code"):
            s["code"] = new_code()
            changed = True
        code = norm(s["code"])
        if code in seen:
            print(f"코드 중복: {s.get('name')}")
            return 1
        seen.add(code)
        payload = {
            "name": s.get("name", ""),
            "notices": common.get("notices", []) + s.get("notices", []),
            "materials": common.get("materials", []) + s.get("materials", []),
            "schedule": s.get("schedule", []),
            "assignments": s.get("assignments", []),
            "scores": s.get("scores", []),
        }
        with open(os.path.join(out_dir, file_id(code) + ".bin"), "wb") as f:
            f.write(encrypt(code, payload))
        print(f"{s.get('name', '?'):<10} {s['code']}")

    if changed:
        with open(os.path.join(ROOT, "students.json"), "w", encoding="utf-8") as f:
            json.dump(students, f, ensure_ascii=False, indent=2)
        print("\n새 코드를 students.json 에 저장했습니다.")
    print(f"\n{len(students)}명 빌드 완료 -> data/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
