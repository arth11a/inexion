"""
miner.py: майнер INEXION. Берёт шаблон блока у вашего узла, перебирает nonce на всех ядрах
процессора и отправляет найденный блок узлу.

  python3 miner.py --node http://127.0.0.1:9333 --address INX...ВАШ_АДРЕС

Награда за блок (и комиссии) приходит на указанный адрес. Адрес создаётся кошельком (wallet.py new).
Python-майнер медленный: для серьёзного майнинга понадобится майнер на C/GPU, протокол у него тот же.
"""
import argparse
import hashlib
import json
import multiprocessing as mp
import os
import sys
import time
import urllib.error
import urllib.request

import core as C
import netutil

CHUNK = 40_000


def _get(url, timeout=8):
    with urllib.request.urlopen(url, timeout=timeout, context=netutil.CONTEXT) as r:
        return json.loads(r.read())


def _post(url, data, timeout=15):
    req = urllib.request.Request(url, data=json.dumps(data).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=netutil.CONTEXT) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")


def scan(args):
    prefix, target, start, count = args
    sha = hashlib.sha256
    for n in range(start, start + count):
        if int.from_bytes(sha(sha(prefix + str(n).encode()).digest()).digest(), "big") <= target:
            return n
    return None


def mine_forever(node, address, workers, log=print, max_blocks=None):
    node = node.rstrip("/")
    found_blocks = 0
    with mp.Pool(workers) as pool:
        while max_blocks is None or found_blocks < max_blocks:
            try:
                tpl = _get("%s/api/template?address=%s" % (node, address))
            except (urllib.error.URLError, OSError, ValueError) as e:
                log("Узел недоступен (%s), повтор через 5 с" % e)
                time.sleep(5)
                continue
            target = int(tpl["target"], 16)
            t = max(tpl["min_time"], int(time.time()))
            prefix = C.header_prefix(tpl["height"], tpl["prev"], tpl["merkle"], t, tpl["target"])
            base, started, last_check, hashes = 0, time.time(), time.time(), 0
            nonce = None
            while nonce is None:
                results = pool.map(scan, [(prefix, target, base + i * CHUNK, CHUNK) for i in range(workers)])
                hashes += workers * CHUNK
                base += workers * CHUNK
                nonce = next((r for r in results if r is not None), None)
                if nonce is not None:
                    break
                if time.time() - last_check > 1.0:              # вершина сменилась или шаблон устарел?
                    last_check = time.time()
                    try:
                        if _get(node + "/api/status")["tip"] != tpl["prev"] or time.time() - started > 25:
                            break
                    except (urllib.error.URLError, OSError, ValueError):
                        break
            if nonce is None:
                continue
            block = {"height": tpl["height"], "prev": tpl["prev"], "merkle": tpl["merkle"], "time": t,
                     "target": tpl["target"], "nonce": nonce, "txs": tpl["txs"],
                     "hash": C.sha256d(prefix + str(nonce).encode()).hex()}
            res = _post(node + "/api/block", block)
            rate = hashes / max(time.time() - started, 1e-9)
            if res.get("status") == "accepted":
                found_blocks += 1
                log("Блок #%d найден и принят (%.0f хеш/с), награда %s INX" % (
                    block["height"], rate, C.format_amount(tpl["txs"][0]["amount"])))
            else:
                log("Блок #%d не принят: %s" % (block["height"], res.get("error") or res.get("status")))
    return found_blocks


def main():
    ap = argparse.ArgumentParser(description="Майнер INEXION")
    ap.add_argument("--node", default="http://127.0.0.1:9333", help="адрес вашего узла")
    ap.add_argument("--address", required=True, help="адрес INX для награды")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1, help="число процессов")
    ap.add_argument("--blocks", type=int, help="остановиться после N найденных блоков")
    args = ap.parse_args()
    if not C.is_valid_address(args.address):
        print("Неверный адрес. Создайте кошелёк: python3 wallet.py new")
        sys.exit(1)
    print("Майнинг на %d процессах. Остановка: Ctrl+C" % args.workers)
    try:
        mine_forever(args.node, args.address, args.workers, max_blocks=args.blocks)
    except KeyboardInterrupt:
        print("\nОстановлено")


if __name__ == "__main__":
    mp.freeze_support()
    main()
