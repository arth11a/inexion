"""
genesis.py: создаёт и проверяет ПЕРВЫЙ БЛОК INEXION. Это точка отсчёта всей сети.

  python3 genesis.py create --founder INX...ВАШ_АДРЕС --message "текст" --bits 26 --time 1793000000
  python3 genesis.py verify genesis.json

Как это работает:
  - В первый блок записывается доля основателя: 2 100 000 INX на ваш адрес. Она заморожена и размораживается
    линейно за 2 года (правило сети, обойти его нельзя: узлы отвергнут перевод заморожённой части).
  - Остальные 90% нельзя получить иначе, чем майнингом.
  - Хеш этого блока и есть идентификатор сети (chain_id). Опубликуйте файл genesis.json и его хеш: все
    узлы должны запускаться с ОДНИМ И ТЕМ ЖЕ файлом. Изменить генезис после запуска нельзя: это будет другая сеть.

Время запуска: блоки принимаются, если их время не дальше 2 часов в будущем. Поэтому --time в будущем
задаёт момент старта: раньше (минус 2 часа) никто не сможет майнить. Это способ запустить сеть для всех сразу.
Сложность: --bits это число нулевых бит в хеше (26 = около 67 млн хешей на блок в начале). Дальше она
подстраивается сама каждые 144 блока. Слишком лёгкая начальная сложность даёт преимущество тем, кто успеет первым.
"""
import argparse
import hashlib
import multiprocessing as mp
import json
import os
import sys
import time

import core as C


def main():
    ap = argparse.ArgumentParser(description="Первый блок INEXION")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--founder", required=True, help="адрес основателя (из wallet.py)")
    c.add_argument("--message", default="INEXION genesis")
    c.add_argument("--time", type=int, default=None, help="время блока (unix), по умолчанию сейчас")
    c.add_argument("--bits", type=int, default=26)
    c.add_argument("--workers", type=int, default=os.cpu_count() or 1, help="число процессов для майнинга блока")
    c.add_argument("--out", default="genesis.json")
    c.add_argument("--force", action="store_true")
    v = sub.add_parser("verify")
    v.add_argument("file")
    a = ap.parse_args()

    if a.cmd == "create":
        if os.path.exists(a.out) and not a.force:
            sys.exit("%s уже существует. Генезис нельзя менять после запуска сети. Укажите другой --out." % a.out)
        t = int(time.time()) if a.time is None else a.time
        print("Майню первый блок (сложность %d бит)…" % a.bits)
        try:
            g = mine_parallel(a.founder, a.message, t, a.bits, a.workers)
        except ValueError as e:
            sys.exit(str(e))
        with open(a.out, "w") as f:
            json.dump(g, f, indent=2)
        print("Готово: %s" % a.out)
        verify_report(g)
    else:
        with open(a.file) as f:
            verify_report(json.load(f))


def _scan(args):
    prefix, target, start, step = args
    sha, n = hashlib.sha256, start
    while True:
        if int.from_bytes(sha(sha(prefix + str(n).encode()).digest()).digest(), "big") <= target:
            return n
        n += step


def mine_parallel(founder, message, t, bits, workers):
    """То же, что core.mine_genesis, но на нескольких процессах."""
    g = C.mine_genesis(founder, message, t, 1)          # заготовка: проверка входных данных и структура блока
    b = g["block"]
    b["target"] = "%064x" % ((1 << (256 - bits)) - 1)
    prefix = C.header_prefix(0, b["prev"], b["merkle"], b["time"], b["target"])
    target = int(b["target"], 16)
    with mp.Pool(workers) as pool:
        for n in pool.imap_unordered(_scan, [(prefix, target, i, workers) for i in range(workers)]):
            pool.terminate()
            b["nonce"] = n
            b["hash"] = C.sha256d(prefix + str(n).encode()).hex()
            return g


def verify_report(g):
    try:
        p = C.Params(g)
    except C.ConsensusError as e:
        sys.exit("Генезис НЕВЕРЕН: %s" % e)
    print("Генезис верен.")
    print("  chain_id (хеш первого блока): %s" % p.chain_id)
    print("  основатель:   %s" % p.founder)
    print("  доля:         %s INX, заморожена, линейная разморозка за %d дней" % (
        C.format_amount(C.FOUNDER_ALLOC), p.vest_seconds // 86400))
    print("  время блока:  %s (unix %d)" % (time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(p.genesis_time)),
                                          p.genesis_time))
    print("  сообщение:    %s" % p.block["txs"][0]["note"])
    print("Опубликуйте chain_id и файл genesis.json. Не меняйте их после запуска.")


if __name__ == "__main__":
    mp.freeze_support()
    main()
