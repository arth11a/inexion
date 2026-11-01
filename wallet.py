"""
wallet.py: кошелёк INEXION. Приватный ключ создаётся и хранится только у вас, на сервер он не попадает:
перевод подписывается здесь, в узел уходит уже готовая подпись.

  python3 wallet.py new                         создать кошелёк (wallet.json) и код восстановления
  python3 wallet.py address                     показать адрес
  python3 wallet.py balance --node URL          баланс
  python3 wallet.py send --to ADDR --amount 1.5 --node URL
  python3 wallet.py restore --code КОД          восстановить кошелёк по коду
  python3 wallet.py recovery                    показать код восстановления

ВАЖНО: кто получит файл wallet.json или код восстановления, получит ваши монеты.
Потеряете оба: монеты пропадут навсегда, восстановить их не сможет никто, включая нас.
Файл кошелька шифруется паролем (scrypt + шифр на HMAC-SHA256 с проверкой целостности, только стандартная
библиотека). Пароль спрашивается при создании и при каждом переводе. Забудете пароль: останется код восстановления.
Это самописная схема без внешнего аудита: диск тоже лучше шифровать, а код восстановления хранить на бумаге.
Флаг --no-password создаёт кошелёк без шифрования (только для тестов).
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

import core as C
import netutil

DEFAULT_FILE = "wallet.json"


def _get(url):
    with urllib.request.urlopen(url, timeout=10, context=netutil.CONTEXT) as r:
        return json.loads(r.read())


def _post(url, data):
    req = urllib.request.Request(url, data=json.dumps(data).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=netutil.CONTEXT) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")


def recovery_code(seed):
    """32 байта ключа + 4 байта контрольной суммы -> base32 группами по 4 символа."""
    raw = base64.b32encode(seed + C.sha256d(seed)[:4]).decode().rstrip("=")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def parse_recovery_code(code):
    raw = "".join(ch for ch in code.upper() if ch.isalnum())       # дефисы, пробелы и переводы строк не важны
    try:
        data = base64.b32decode(raw + "=" * (-len(raw) % 8))
    except ValueError:
        raise ValueError("код восстановления введён неверно")
    # строго: запись должна быть канонической, иначе опечатка в «пустых» битах последнего символа прошла бы незамеченной
    if len(data) != 36 or base64.b32encode(data).decode().rstrip("=") != raw:
        raise ValueError("код восстановления введён неверно: проверьте, нет ли опечатки")
    if C.sha256d(data[:32])[:4] != data[32:]:
        raise ValueError("контрольная сумма кода не сходится: проверьте, нет ли опечатки")
    seed = data[:32]
    if not 0 < int.from_bytes(seed, "big") < C.N:
        raise ValueError("код восстановления недействителен")
    return seed


def wallet_from_seed(seed):
    priv = int.from_bytes(seed, "big")
    pub = C.pubkey_from_priv(priv)
    return {"version": 1, "address": C.address_from_pub(pub), "public_key": pub.hex(), "seed": seed.hex()}


# ------------------------------------------------------------------ шифрование файла кошелька
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


def _keys(password, salt, n=SCRYPT_N):
    k = hashlib.scrypt(password.encode(), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, maxmem=128 * 1024 * 1024, dklen=64)
    return k[:32], k[32:]


def _stream(key, nonce, length):
    out, i = b"", 0
    while len(out) < length:
        out += hmac.new(key, nonce + i.to_bytes(8, "big"), hashlib.sha256).digest()
        i += 1
    return out[:length]


def encrypt_seed(seed, password, n=SCRYPT_N):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    ek, mk = _keys(password, salt, n)
    ct = bytes(a ^ b for a, b in zip(seed, _stream(ek, nonce, len(seed))))
    tag = hmac.new(mk, salt + nonce + ct, hashlib.sha256).digest()
    return {"kdf": "scrypt", "n": n, "salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex(), "tag": tag.hex()}


def decrypt_seed(enc, password):
    salt, nonce, ct = bytes.fromhex(enc["salt"]), bytes.fromhex(enc["nonce"]), bytes.fromhex(enc["ct"])
    if enc.get("kdf") != "scrypt" or enc["n"] > 2 ** 20:
        raise ValueError("неизвестный формат шифрования")
    ek, mk = _keys(password, salt, enc["n"])
    if not hmac.compare_digest(hmac.new(mk, salt + nonce + ct, hashlib.sha256).digest(), bytes.fromhex(enc["tag"])):
        raise ValueError("неверный пароль или файл повреждён")
    return bytes(a ^ b for a, b in zip(ct, _stream(ek, nonce, len(ct))))


def ask_password(confirm=False):
    pw = os.environ.get("INX_WALLET_PASSWORD")        # для автоматизации и тестов; вручную вводите в запросе
    if pw is not None:
        return pw
    if not sys.stdin.isatty():
        sys.exit("Нужен пароль кошелька: запустите в Терминале или задайте INX_WALLET_PASSWORD.")
    pw = getpass.getpass("Пароль кошелька: ")
    if confirm and getpass.getpass("Повторите пароль: ") != pw:
        sys.exit("Пароли не совпали.")
    return pw


def save_wallet(w, path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # O_EXCL: не перезаписываем чужой кошелёк
    with os.fdopen(fd, "w") as f:
        json.dump(w, f, indent=2)


def load_wallet(path):
    try:
        with open(path) as f:
            w = json.load(f)
        if "enc" in w:
            seed = decrypt_seed(w["enc"], ask_password())
            w["seed"] = seed.hex()
        else:
            seed = bytes.fromhex(w["seed"])
        if wallet_from_seed(seed)["address"] != w["address"]:
            raise ValueError("файл кошелька повреждён")
        return w, int.from_bytes(seed, "big")
    except (OSError, ValueError, KeyError) as e:
        sys.exit("Не удалось открыть кошелёк %s: %s" % (path, e))


def main():
    ap = argparse.ArgumentParser(description="Кошелёк INEXION")
    ap.add_argument("cmd", choices=["new", "restore", "address", "balance", "send", "recovery"])
    ap.add_argument("--file", default=DEFAULT_FILE)
    ap.add_argument("--node", default="http://127.0.0.1:9333")
    ap.add_argument("--to")
    ap.add_argument("--amount")
    ap.add_argument("--fee", default="0.0001")
    ap.add_argument("--code")
    ap.add_argument("--address")
    ap.add_argument("--yes", action="store_true", help="не спрашивать подтверждение")
    ap.add_argument("--no-password", action="store_true", help="не шифровать файл кошелька (только для тестов)")
    a = ap.parse_args()

    if a.cmd in ("new", "restore"):
        if os.path.exists(a.file):
            sys.exit("Файл %s уже существует, ничего не перезаписываю. Укажите другой --file." % a.file)
        if a.cmd == "new":
            seed = secrets.token_bytes(32)
            while not 0 < int.from_bytes(seed, "big") < C.N:
                seed = secrets.token_bytes(32)
        else:
            if not a.code:
                sys.exit("Укажите --code КОД")
            try:
                seed = parse_recovery_code(a.code)
            except ValueError as e:
                sys.exit(str(e))
        w = wallet_from_seed(seed)
        if a.no_password:
            to_save = w
        else:
            pw = ask_password(confirm=True)
            if len(pw) < 10:
                sys.exit("Пароль слишком короткий: нужно не меньше 10 символов.")
            to_save = {k: v for k, v in w.items() if k != "seed"}
            to_save["enc"] = encrypt_seed(seed, pw)
        save_wallet(to_save, a.file)
        print("Кошелёк сохранён в %s%s" % (a.file, "" if a.no_password else " (зашифрован паролем)"))
        print("Ваш адрес (его можно показывать): %s" % w["address"])
        if a.cmd == "new":
            print("\nКОД ВОССТАНОВЛЕНИЯ (запишите на бумагу и спрячьте, никому не показывайте):")
            print("  " + recovery_code(seed))
            print("\nБез файла или этого кода монеты не вернуть. С ними их может забрать кто угодно.")
        return

    w, priv = load_wallet(a.file)
    if a.cmd == "address":
        print(w["address"])
    elif a.cmd == "recovery":
        print("Код восстановления (никому не показывайте):\n  " + recovery_code(bytes.fromhex(w["seed"])))
    elif a.cmd == "balance":
        info = _get("%s/api/account/%s" % (a.node.rstrip("/"), a.address or w["address"]))
        print("Адрес:        %s" % info["address"])
        print("Баланс:       %s INX" % C.format_amount(info["balance"]))
        print("Заморожено:   %s INX" % C.format_amount(info["locked"]))
        print("Можно потратить: %s INX" % C.format_amount(info["spendable"]))
    elif a.cmd == "send":
        if not a.to or not a.amount:
            sys.exit("Нужны --to и --amount")
        if not C.is_valid_address(a.to):
            sys.exit("Адрес получателя неверный (контрольная сумма не сходится)")
        try:
            amount, fee = C.parse_amount(a.amount), C.parse_amount(a.fee)
        except ValueError as e:
            sys.exit(str(e))
        node = a.node.rstrip("/")
        st = _get(node + "/api/status")
        info = _get("%s/api/account/%s" % (node, w["address"]))
        print("Сеть:        %s (chain_id %s…)" % (st["ticker"], st["chain_id"][:16]))
        print("Отправить:   %s INX на %s" % (C.format_amount(amount), a.to))
        print("Комиссия:    %s INX" % C.format_amount(fee))
        if not a.yes and input("Подтвердить (yes/no)? ").strip().lower() != "yes":
            sys.exit("Отменено.")
        tx = C.make_transfer(priv, st["chain_id"], a.to, amount, fee, info["pending_nonce"])
        res = _post(node + "/api/tx", tx)
        if "txid" in res:
            print("Перевод отправлен. txid: %s\nОн подтвердится, когда попадёт в блок." % res["txid"])
        else:
            sys.exit("Узел отклонил перевод: %s" % res.get("error"))


if __name__ == "__main__":
    main()
