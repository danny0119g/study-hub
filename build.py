#!/usr/bin/env python3
"""students.json + common.json -> data/<id>.bin (학생별 암호화 파일).

사용법:  python3 build.py
- 학생 코드는 학생 휴대폰 번호 뒤 8자리(010 제외)이며, students.json 의 code 에 반드시 적는다.
- students.json 은 내 컴퓨터에만 둔다(.gitignore). 저장소에는 data/*.bin 만 올라간다.
"""
import hashlib
import json
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 600_000
ID_SALT = b"study-hub-id"
ROOT = os.path.dirname(os.path.abspath(__file__))


def norm(code: str) -> str:
    """정규형: 숫자 8자리 (웹페이지의 norm 과 동일해야 함). 010 포함 11자리면 010 을 뗀다."""
    digits = re.sub(r"\D", "", str(code))
    if len(digits) == 11 and digits.startswith("010"):
        digits = digits[3:]
    return digits


def file_id(code: str) -> str:
    # 느린 해시(PBKDF2)를 써야 data/ 의 파일명만으로 코드를 빠르게 역산할 수 없다.
    return hashlib.pbkdf2_hmac("sha256", code.encode(), ID_SALT, ITER, dklen=8).hex()


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

    seen = set()
    for s in students:
        code = norm(s.get("code", ""))
        if not re.fullmatch(r"\d{8}", code):
            print(f"코드는 숫자 8자리여야 합니다: {s.get('name')} ({s.get('code')!r})")
            return 1
        if code in seen:
            print(f"코드 중복: {s.get('name')}")
            return 1
        seen.add(code)
        payload = {
            "name": s.get("name", ""),
            "notices": common.get("notices", []) + s.get("notices", []),
            "materials": common.get("materials", []) + s.get("materials", []),
            "schedule": s.get("schedule", []),
            "weekly": s.get("weekly", []),
            "skip": s.get("skip", []),
            "assignments": s.get("assignments", []),
            "scores": s.get("scores", []),
        }
        with open(os.path.join(out_dir, file_id(code) + ".bin"), "wb") as f:
            f.write(encrypt(code, payload))
        print(f"{s.get('name', '?'):<10} {code}")

    print(f"\n{len(students)}명 빌드 완료 -> data/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
