"""
difficulty.py: подбор стартовой сложности (--bits) под реальную мощность и оценка, сколько монет
успеют намайнить за сутки до выравнивания сложности.

  python3 difficulty.py                      # замерит ваш компьютер
  python3 difficulty.py --mhs 5 --attacker-x 1000
"""
import argparse, hashlib, math, os, time

BLOCK_TIME, RETARGET, CLAMP, REWARD = 60, 144, 4, 4.5


def measure(seconds=3):
    p = b"INEXBLK|1|" + b"00" * 32 + b"|" + b"11" * 32 + b"|1793000000|" + b"ff" * 32 + b"|"
    sha, n, t = hashlib.sha256, 0, time.time()
    while time.time() - t < seconds:
        for _ in range(20000):
            sha(sha(p + str(n).encode()).digest()).digest()
            n += 1
    return n / (time.time() - t) * (os.cpu_count() or 1) / 1e6


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mhs", type=float, help="мощность сети в МХеш/с (по умолчанию замер этого компьютера)")
    ap.add_argument("--attacker-x", type=float, default=1000, help="во сколько раз мощнее майнер на C/GPU")
    a = ap.parse_args()
    mhs = a.mhs or measure()
    print("Мощность Python-майнера: %.1f МХеш/с" % mhs)
    print("\nbits | сек/блок для Python-майнера | сек/блок для майнера в %dx мощнее" % a.attacker_x)
    for bits in range(24, 41, 2):
        print("%4d | %27.1f | %.2f" % (bits, 2 ** bits / (mhs * 1e6), 2 ** bits / (mhs * 1e6 * a.attacker_x)))
    rec = round(math.log2(mhs * 1e6 * BLOCK_TIME * 2))
    print("\nРекомендация: --bits %d (около %.0f с на блок для Python-майнера, т.е. ~2 минуты)" % (
        rec, 2 ** rec / (mhs * 1e6)))
    steps = math.ceil(math.log(a.attacker_x, CLAMP))
    blocks = steps * RETARGET
    print("Если придёт майнер в %dx мощнее: сложность выровняется за ~%d блоков (~%.0f INX успеет забрать он,"
          " лимит роста 4x за %d блоков)." % (a.attacker_x, blocks, blocks * REWARD, RETARGET))
    print("Выше --bits не ставьте без мощности: сеть будет стоять. Сложность вниз сама падает не ниже 24 бит.")


if __name__ == "__main__":
    main()
