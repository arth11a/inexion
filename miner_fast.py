"""
miner_fast.py: быстрый майнер INEXION. Сеть, шаблоны блоков и отправка блоков как в miner.py (на Python),
а перебор nonce делает программа на C (inxscan) на всех ядрах: аппаратный SHA-256 на Apple Silicon и на
процессорах Intel/AMD с SHA-NI (Intel с Ice Lake, AMD с Zen).

  python3 miner_fast.py --node http://127.0.0.1:9333 --address INX...ВАШ_АДРЕС

Где берётся inxscan: сначала готовая сборка из папки bin/ (в релизных архивах), затем сборка из inxscan.c
(нужен компилятор C). Если нет ни того ни другого, майнер сам переходит на медленный Python-вариант.
Протокол тот же, что у miner.py: узлы не отличают этих майнеров.
"""
import argparse
import os
import platform
import subprocess
import sys
import time
import urllib.error

import core as C
import miner as M

HERE = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
if getattr(sys, "frozen", False) and HERE.endswith(os.path.join("Contents", "MacOS")):   # приложение INEXION.app
    HERE = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))                      # папка, где лежит .app и bin/
SRC = os.path.join(HERE, "inxscan.c")
_ARCH = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}
_SYS = platform.system().lower()
_MACH = _ARCH.get(platform.machine().lower(), platform.machine().lower())
NAME = "inxscan-%s-%s%s" % (_SYS, _MACH, ".exe" if _SYS == "windows" else "")
PREBUILT = os.path.join(HERE, "bin", NAME)       # готовая сборка из релизного архива
BUILT = os.path.join(HERE, NAME)                  # собранная здесь из inxscan.c
FLAGS = [["-O2", "-mcpu=native"], ["-O2", "-march=armv8-a+crypto"], ["-O2"]]
BIN = None


def _impl(path):
    """Имя реализации SHA-256, если программа запускается; иначе None."""
    try:
        r = subprocess.run([path, "--impl"], capture_output=True, text=True, timeout=15)
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except (OSError, subprocess.SubprocessError):
        return None


def build(log=print):
    """Собирает inxscan из inxscan.c; на ARM выбирает вариант с аппаратным SHA-256, если он собирается."""
    if not os.path.exists(SRC):
        raise RuntimeError("нет файла inxscan.c")
    arm = _MACH == "arm64"
    best = None
    for flags in FLAGS:
        tmp = BUILT + ".tmp"
        try:
            r = subprocess.run(["cc"] + flags + ["-pthread", "-o", tmp, SRC], capture_output=True, text=True)
        except OSError:
            raise RuntimeError("не найден компилятор C (cc)")
        if r.returncode != 0:
            continue
        impl = _impl(tmp)
        if impl is None:
            continue
        if best is None or (impl != "portable C" and best[1] == "portable C"):
            best = (flags, impl)
            os.replace(tmp, BUILT)
        else:
            os.remove(tmp)
        if not arm or impl != "portable C":
            break
    if best is None:
        raise RuntimeError("не удалось собрать inxscan")
    log("inxscan собран: %s" % best[1])


def ensure_binary(log=print):
    """Выбирает программу перебора. Возвращает путь или бросает RuntimeError."""
    global BIN
    impl = _impl(PREBUILT) if os.path.exists(PREBUILT) else None
    if impl:
        BIN = PREBUILT
        log("Готовая сборка inxscan: %s" % impl)
        return BIN
    if not os.path.exists(BUILT) or (os.path.exists(SRC) and os.path.getmtime(BUILT) < os.path.getmtime(SRC)):
        build(log)
    impl = _impl(BUILT)
    if not impl:
        raise RuntimeError("inxscan не запускается на этом компьютере")
    BIN = BUILT
    log("inxscan: %s" % impl)
    return BIN


def scan(prefix, target_hex, start, count, threads):
    r = subprocess.run([BIN, prefix.hex(), target_hex, str(start), str(count), str(threads)],
                       capture_output=True, text=True, timeout=300)
    out = r.stdout.split()
    if r.returncode != 0 or not out:
        raise RuntimeError("inxscan: " + (r.stderr.strip() or "ошибка"))
    return int(out[1]) if out[0] == "FOUND" else None


def mine_forever(node, address, threads, log=print, max_blocks=None):
    ensure_binary(log)
    node, found_blocks, chunk = node.rstrip("/"), 0, 20_000_000
    while max_blocks is None or found_blocks < max_blocks:
        try:
            tpl = M._get("%s/api/template?address=%s" % (node, address))
        except (urllib.error.URLError, OSError, ValueError) as e:
            log("Узел недоступен (%s), повтор через 5 с" % e)
            time.sleep(5)
            continue
        target = int(tpl["target"], 16)
        t = max(tpl["min_time"], int(time.time()))
        prefix = C.header_prefix(tpl["height"], tpl["prev"], tpl["merkle"], t, tpl["target"])
        base, started, hashes, nonce = 0, time.time(), 0, None
        while nonce is None:
            t0 = time.time()
            nonce = scan(prefix, tpl["target"], base, chunk, threads)
            dt = max(time.time() - t0, 1e-6)
            if nonce is None:
                base += chunk
                hashes += chunk
                chunk = max(1_000_000, min(int(chunk * 1.5 / dt), 2_000_000_000))   # подгоняем под ~1,5 с на порцию
                try:
                    if M._get(node + "/api/status")["tip"] != tpl["prev"] or time.time() - started > 25:
                        break
                except (urllib.error.URLError, OSError, ValueError):
                    break
        if nonce is None:
            continue
        h = C.sha256d(prefix + str(nonce).encode())
        if int.from_bytes(h, "big") > target:
            log("Ошибка: inxscan вернул неверный nonce, пропускаю шаблон")
            continue
        block = {"height": tpl["height"], "prev": tpl["prev"], "merkle": tpl["merkle"], "time": t,
                 "target": tpl["target"], "nonce": nonce, "txs": tpl["txs"], "hash": h.hex()}
        res = M._post(node + "/api/block", block)
        rate = (hashes + (nonce - base)) / max(time.time() - started, 1e-9)
        if res.get("status") == "accepted":
            found_blocks += 1
            log("Блок #%d найден и принят (~%.1f МХеш/с), награда %s INX" % (
                block["height"], rate / 1e6, C.format_amount(tpl["txs"][0]["amount"])))
        else:
            log("Блок #%d не принят: %s" % (block["height"], res.get("error") or res.get("status")))
    return found_blocks


def main():
    ap = argparse.ArgumentParser(description="Быстрый майнер INEXION")
    ap.add_argument("--node", default="http://127.0.0.1:9333", help="адрес вашего узла")
    ap.add_argument("--address", required=True, help="адрес INX для награды")
    ap.add_argument("--threads", type=int, default=os.cpu_count() or 1, help="число потоков")
    ap.add_argument("--blocks", type=int, help="остановиться после N найденных блоков")
    args = ap.parse_args()
    if not C.is_valid_address(args.address):
        sys.exit("Неверный адрес. Создайте кошелёк: python3 wallet.py new")
    try:
        ensure_binary()
    except RuntimeError as e:
        print("Быстрый перебор недоступен (%s). Перехожу на медленный Python-майнер." % e)
        print("Для быстрого майнинга поставьте компилятор C (Mac: xcode-select --install; Linux: sudo apt install build-essential)")
        print("или скачайте готовую сборку для вашей системы на https://inexion.org/download/")
        try:
            M.mine_forever(args.node, args.address, args.threads, max_blocks=args.blocks)
        except KeyboardInterrupt:
            print("\nОстановлено")
        return
    print("Быстрый майнинг на %d потоках. Остановка: Ctrl+C" % args.threads)
    try:
        mine_forever(args.node, args.address, args.threads, max_blocks=args.blocks)
    except KeyboardInterrupt:
        print("\nОстановлено")
    except RuntimeError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
