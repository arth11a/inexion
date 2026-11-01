import copy
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import core as C  # noqa: E402

FOUNDER_PRIV, ALICE_PRIV, BOB_PRIV, MINER_PRIV = 1, 11, 22, 33


def addr(priv):
    return C.address_from_pub(C.pubkey_from_priv(priv))


def make_genesis(bits=8, age_days=20, founder_priv=FOUNDER_PRIV, message="test genesis"):
    """Тестовый первый блок. Это НЕ основная сеть: ключ основателя здесь общеизвестен (priv=1)."""
    return C.mine_genesis(addr(founder_priv), message, int(time.time()) - age_days * 86400, bits)


def fresh_chain(genesis=None):
    return C.Chain(copy.deepcopy(genesis or make_genesis()))


def solve(height, prev, merkle, t, target, txs, avoid=False):
    """Найти nonce. avoid=True: найти nonce, при котором PoW НЕ выполнен (для негативных тестов)."""
    th = "%064x" % target
    prefix = C.header_prefix(height, prev, merkle, t, th)
    n = 0
    while True:
        h = C.sha256d(prefix + str(n).encode())
        ok = int.from_bytes(h, "big") <= target
        if ok != avoid:
            return {"height": height, "prev": prev, "merkle": merkle, "time": t, "target": th, "nonce": n,
                    "txs": txs, "hash": h.hex()}
        n += 1


def build_block(chain, miner, transfers=(), t=None, cb_extra=0, prev=None, height=None, merkle=None,
                target=None, avoid=False):
    h = chain.height + 1 if height is None else height
    fees = sum(x["fee"] for x in transfers)
    cb = {"type": "coinbase", "to": miner, "amount": C.block_reward(h) + fees + cb_extra, "height": h}
    txs = [cb] + list(transfers)
    merkle = merkle or C.merkle_root([C.txid(x) for x in txs])
    t = chain.tip["time"] + 60 if t is None else t
    target = chain.expected_target(h) if target is None else target
    return solve(h, prev or chain.tip["hash"], merkle, t, target, txs, avoid)


def extend(chain, miner, n, transfers_per_block=None, spacing=60, **kw):
    for i in range(n):
        tx = (transfers_per_block or {}).get(i, [])
        chain.add_block(build_block(chain, miner, tx, t=chain.tip["time"] + spacing, **kw))


def transfer(chain, priv, to, amount, fee=10_000, nonce=None, chain_id=None):
    nonce = chain.nonce.get(addr(priv), 0) if nonce is None else nonce
    return C.make_transfer(priv, chain_id or chain.params.chain_id, to, amount, fee, nonce)
