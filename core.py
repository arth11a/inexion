"""
INEXION (INX): правила консенсуса. Только стандартная библиотека Python 3.8+.

Любое изменение констант или правил ниже создаёт ДРУГУЮ монету: узлы со старыми правилами
отвергнут блоки новых. Поэтому после запуска основной сети этот файл менять нельзя.

Что здесь определено:
  - деньги: целые единицы, 1 INX = 10^8 единиц, лимит 21 000 000 INX;
  - распределение: 10% основателю в первом блоке (с линейной заморозкой на 2 года),
    90% только за майнинг: 4,5 INX за блок, халвинг каждые 2 100 000 блоков (около 4 лет);
  - подписи ECDSA secp256k1 (детерминированный nonce по RFC 6979), адреса с контрольной суммой;
  - блоки: proof-of-work (двойной SHA-256), Merkle-корень, ретаргет сложности каждые 144 блока;
  - цепочка с откатом и реорганизацией (побеждает цепочка с наибольшей суммарной работой).
"""
import hashlib
import hmac
import json
import time
from decimal import Decimal, InvalidOperation

# ------------------------------------------------------------------ параметры монеты
COIN_NAME = "INEXION"
TICKER = "INX"
PROTOCOL_VERSION = 1
DECIMALS = 8
UNIT = 10 ** DECIMALS
MAX_SUPPLY = 21_000_000 * UNIT
FOUNDER_ALLOC = MAX_SUPPLY // 10                  # 2 100 000 INX, выдаются в первом блоке
MINER_SUPPLY = MAX_SUPPLY - FOUNDER_ALLOC         # 18 900 000 INX, только майнерам
HALVING_INTERVAL = 2_100_000
INITIAL_REWARD = MINER_SUPPLY // (2 * HALVING_INTERVAL)   # 4,5 INX (450 000 000 единиц)
BLOCK_TIME = 60                                   # целевое время блока, секунды
RETARGET_INTERVAL = 144                           # пересчёт сложности каждые N блоков
MIN_FEE = 1_000                                   # 0.00001 INX
MAX_BLOCK_TXS = 1_000                             # переводов в блоке (без coinbase)
MAX_BLOCK_BYTES = 1_000_000
VEST_SECONDS = 2 * 365 * 24 * 3600                # доля основателя размораживается линейно 2 года
MAX_FUTURE_DRIFT = 2 * 3600
MTP_WINDOW = 11
FLOOR_BITS = 24                                   # сложность никогда не опускается ниже 2^24 хешей на блок
MAX_NOTE = 200
MAX_NONCE_TX = 2 ** 63

HEX = set("0123456789abcdef")


class ConsensusError(Exception):
    """Блок или транзакция нарушают правила сети."""


# ------------------------------------------------------------------ утилиты
def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return sha256(sha256(b))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def is_hex(s, n=None):
    return isinstance(s, str) and (n is None or len(s) == n) and all(c in HEX for c in s)


def is_int(x):
    return type(x) is int


def format_amount(units):
    sign = "-" if units < 0 else ""
    units = abs(units)
    return "%s%d.%08d" % (sign, units // UNIT, units % UNIT)


def parse_amount(text):
    """'1.5' -> 150000000. Больше 8 знаков после запятой, отрицательные и нулевые суммы отвергаются."""
    try:
        d = Decimal(str(text).strip())
    except InvalidOperation:
        raise ValueError("некорректная сумма: %r" % (text,))
    if not d.is_finite() or d <= 0:
        raise ValueError("сумма должна быть больше нуля")
    scaled = d * UNIT
    if scaled != scaled.to_integral_value():
        raise ValueError("не больше %d знаков после запятой" % DECIMALS)
    return int(scaled)


# ------------------------------------------------------------------ base58 и адреса
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def b58decode(s):
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            raise ValueError("недопустимый символ в адресе")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def address_from_pub(pub):
    payload = sha256d(pub)[:20]
    return "INX" + b58encode(payload + sha256d(payload)[:4])


def is_valid_address(addr):
    if not isinstance(addr, str) or not addr.startswith("INX") or not (20 <= len(addr) <= 50):
        return False
    try:
        raw = b58decode(addr[3:])
    except ValueError:
        return False
    return len(raw) == 24 and sha256d(raw[:20])[:4] == raw[20:]


# ------------------------------------------------------------------ ECDSA secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _inv(a, m):
    return pow(a, -1, m)


def _jdouble(p):
    if p is None:
        return None
    x, y, z = p
    if y == 0:
        return None
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    return (x3, (m * (s - x3) - 8 * yy * yy) % P, 2 * y * z % P)


def _jadd(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1, z2z2 = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2z2 % P, x2 * z1z1 % P
    s1, s2 = y1 * z2 * z2z2 % P, y2 * z1 * z1z1 % P
    if u1 == u2:
        return _jdouble(p) if s1 == s2 else None
    h, r = (u2 - u1) % P, (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    v = u1 * h2 % P
    x3 = (r * r - h3 - 2 * v) % P
    return (x3, (r * (v - x3) - s1 * h3) % P, h * z1 * z2 % P)


def _affine(p):
    if p is None:
        return None
    x, y, z = p
    zi = _inv(z, P)
    zi2 = zi * zi % P
    return (x * zi2 % P, y * zi2 * zi % P)


def _jmul(k, pt):
    k %= N
    res, add = None, (pt[0], pt[1], 1)
    while k:
        if k & 1:
            res = _jadd(res, add)
        add = _jdouble(add)
        k >>= 1
    return res


def point_mul(k, pt=G):
    return _affine(_jmul(k, pt))


def pubkey_from_priv(priv):
    """Сжатый публичный ключ (33 байта) из приватного числа 1..N-1."""
    if not 0 < priv < N:
        raise ValueError("приватный ключ вне диапазона")
    x, y = point_mul(priv)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def decompress(pub):
    if len(pub) != 33 or pub[0] not in (2, 3):
        return None
    x = int.from_bytes(pub[1:], "big")
    if x >= P:
        return None
    rhs = (pow(x, 3, P) + 7) % P
    y = pow(rhs, (P + 1) // 4, P)
    if y * y % P != rhs:
        return None
    if (y & 1) != (pub[0] & 1):
        y = P - y
    return (x, y)


def _rfc6979(priv, z_bytes):
    x = priv.to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + z_bytes, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + z_bytes, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(priv, digest):
    """Подпись ECDSA (r||s в hex, 128 символов, s в нижней половине: подпись не подделать «зеркалом»)."""
    z = int.from_bytes(digest, "big") % N
    k = _rfc6979(priv, z.to_bytes(32, "big"))
    r = point_mul(k)[0] % N
    s = _inv(k, N) * (z + r * priv) % N
    if s > N // 2:
        s = N - s
    return "%064x%064x" % (r, s)


def verify(pub, digest, sig_hex):
    if not is_hex(sig_hex, 128):
        return False
    r, s = int(sig_hex[:64], 16), int(sig_hex[64:], 16)
    if not (0 < r < N and 0 < s <= N // 2):
        return False
    q = decompress(pub)
    if q is None:
        return False
    z = int.from_bytes(digest, "big") % N
    w = _inv(s, N)
    pt = _affine(_jadd(_jmul(z * w % N, G), _jmul(r * w % N, q)))
    return pt is not None and pt[0] % N == r


# ------------------------------------------------------------------ транзакции
def tx_digest(chain_id, from_pub, to, amount, fee, nonce):
    """Что именно подписывает владелец. chain_id защищает от повторной отправки подписи в другой сети."""
    return sha256d(("INEXION-TX|%s|%s|%s|%d|%d|%d" % (chain_id, from_pub, to, amount, fee, nonce)).encode())


def make_transfer(priv, chain_id, to, amount, fee, nonce):
    pub = pubkey_from_priv(priv).hex()
    return {"type": "transfer", "from_pub": pub, "to": to, "amount": amount, "fee": fee, "nonce": nonce,
            "sig": sign(priv, tx_digest(chain_id, pub, to, amount, fee, nonce))}


def txid(tx):
    return sha256d(canonical(tx)).hex()


def tx_sender(tx):
    return address_from_pub(bytes.fromhex(tx["from_pub"]))


def check_transfer_schema(tx):
    if not isinstance(tx, dict) or set(tx) != {"type", "from_pub", "to", "amount", "fee", "nonce", "sig"}:
        raise ConsensusError("неверная структура перевода")
    if tx["type"] != "transfer" or not is_hex(tx["from_pub"], 66) or not is_hex(tx["sig"], 128):
        raise ConsensusError("неверные поля перевода")
    if not is_valid_address(tx["to"]):
        raise ConsensusError("неверный адрес получателя")
    if not (is_int(tx["amount"]) and 0 < tx["amount"] <= MAX_SUPPLY):
        raise ConsensusError("неверная сумма")
    if not (is_int(tx["fee"]) and MIN_FEE <= tx["fee"] <= MAX_SUPPLY):
        raise ConsensusError("комиссия меньше минимальной (%s INX)" % format_amount(MIN_FEE))
    if not (is_int(tx["nonce"]) and 0 <= tx["nonce"] < MAX_NONCE_TX):
        raise ConsensusError("неверный nonce")


def check_coinbase_schema(tx):
    if not isinstance(tx, dict) or set(tx) != {"type", "to", "amount", "height"} or tx["type"] != "coinbase":
        raise ConsensusError("неверная структура coinbase")
    if not is_valid_address(tx["to"]) or not (is_int(tx["amount"]) and 0 <= tx["amount"] <= MAX_SUPPLY) \
            or not (is_int(tx["height"]) and tx["height"] >= 1):
        raise ConsensusError("неверные поля coinbase")


# ------------------------------------------------------------------ блоки
def merkle_root(ids):
    layer = [bytes.fromhex(i) for i in ids]
    if not layer:
        return "00" * 32
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0].hex()


def header_prefix(height, prev, merkle, t, target_hex):
    return ("INEXBLK|%d|%s|%s|%d|%s|" % (height, prev, merkle, t, target_hex)).encode()


def block_hash(b):
    return sha256d(header_prefix(b["height"], b["prev"], b["merkle"], b["time"], b["target"])
                   + str(b["nonce"]).encode()).hex()


def block_work(b):
    return (1 << 256) // (int(b["target"], 16) + 1)


def block_reward(height):
    return INITIAL_REWARD >> ((height - 1) // HALVING_INTERVAL) if height >= 1 else 0


def mined_supply_through(height):
    """Сколько INX выдано майнерам блоками 1..height (комиссии не считаются: это не новые монеты)."""
    total, e = 0, 0
    while True:
        reward = INITIAL_REWARD >> e
        if reward == 0:
            return total
        first, last = e * HALVING_INTERVAL + 1, (e + 1) * HALVING_INTERVAL
        n = min(height, last) - first + 1
        if n <= 0:
            return total
        total += n * reward
        e += 1


def check_block_schema(b):
    keys = {"height", "prev", "merkle", "time", "target", "nonce", "txs", "hash"}
    if not isinstance(b, dict) or set(b) != keys:
        raise ConsensusError("неверная структура блока")
    if not (is_int(b["height"]) and b["height"] >= 0 and is_int(b["time"]) and 0 <= b["time"] < 2 ** 40
            and is_int(b["nonce"]) and 0 <= b["nonce"] < 2 ** 64):
        raise ConsensusError("неверные числовые поля блока")
    for k in ("prev", "merkle", "target", "hash"):
        if not is_hex(b[k], 64):
            raise ConsensusError("неверное поле блока: " + k)
    if not isinstance(b["txs"], list) or not 1 <= len(b["txs"]) <= MAX_BLOCK_TXS + 1:
        raise ConsensusError("неверное число транзакций в блоке")
    if len(canonical(b)) > MAX_BLOCK_BYTES:
        raise ConsensusError("блок слишком большой")


# ------------------------------------------------------------------ первый блок
def mine_genesis(founder, message, t, bits):
    """Создаёт и майнит первый блок. bits: сколько нулевых бит в начале хеша (начальная сложность)."""
    if not is_valid_address(founder):
        raise ValueError("неверный адрес основателя")
    if not 1 <= bits <= 64:
        raise ValueError("bits должно быть от 1 до 64")
    if len(message) > MAX_NOTE:
        raise ValueError("сообщение длиннее %d символов" % MAX_NOTE)
    tx = {"type": "allocation", "to": founder, "amount": FOUNDER_ALLOC, "vesting_seconds": VEST_SECONDS,
          "note": message}
    block = {"height": 0, "prev": "00" * 32, "merkle": merkle_root([txid(tx)]), "time": int(t),
             "target": "%064x" % ((1 << (256 - bits)) - 1), "nonce": 0, "txs": [tx], "hash": ""}
    prefix = header_prefix(0, block["prev"], block["merkle"], block["time"], block["target"])
    target = int(block["target"], 16)
    n = 0
    while True:
        h = sha256d(prefix + str(n).encode())
        if int.from_bytes(h, "big") <= target:
            block["nonce"], block["hash"] = n, h.hex()
            return {"coin": COIN_NAME, "ticker": TICKER, "protocol": PROTOCOL_VERSION, "block": block}
        n += 1


class Params:
    """Параметры сети, выведенные из первого блока. chain_id = хеш первого блока."""

    def __init__(self, genesis):
        if not isinstance(genesis, dict) or genesis.get("coin") != COIN_NAME or genesis.get("ticker") != TICKER \
                or genesis.get("protocol") != PROTOCOL_VERSION:
            raise ConsensusError("это не генезис INEXION этой версии протокола")
        b = genesis.get("block")
        check_block_schema(b)
        if b["height"] != 0 or b["prev"] != "00" * 32 or len(b["txs"]) != 1:
            raise ConsensusError("неверный первый блок")
        tx = b["txs"][0]
        if not isinstance(tx, dict) or set(tx) != {"type", "to", "amount", "vesting_seconds", "note"} \
                or tx["type"] != "allocation" or not is_valid_address(tx["to"]) \
                or tx["amount"] != FOUNDER_ALLOC or tx["vesting_seconds"] != VEST_SECONDS \
                or not isinstance(tx["note"], str) or len(tx["note"]) > MAX_NOTE:
            raise ConsensusError("в первом блоке неверная доля основателя")
        if merkle_root([txid(tx)]) != b["merkle"] or block_hash(b) != b["hash"]:
            raise ConsensusError("первый блок: неверный хеш или Merkle-корень")
        target = int(b["target"], 16)
        if not 0 < target < (1 << 255) or int(b["hash"], 16) > target:
            raise ConsensusError("первый блок: proof-of-work не выполнен")
        self.block = b
        self.chain_id = b["hash"]
        self.founder = tx["to"]
        self.genesis_time = b["time"]
        self.vest_seconds = tx["vesting_seconds"]
        # Самая лёгкая допустимая цель: не легче FLOOR_BITS, но и не жёстче стартовой. Так стартовую сложность можно
        # поставить высокой, а если майнеры уйдут, сеть сама снизит её (не встанет навсегда).
        self.pow_limit = max(target, (1 << (256 - FLOOR_BITS)) - 1)

    def locked(self, addr, t):
        """Сколько единиц на адресе заморожено в момент t (только для основателя, линейно до нуля)."""
        if addr != self.founder:
            return 0
        remaining = min(self.vest_seconds, self.genesis_time + self.vest_seconds - t)
        return FOUNDER_ALLOC * remaining // self.vest_seconds if remaining > 0 else 0


# ------------------------------------------------------------------ состояние и цепочка
class Overlay:
    """Изменения балансов поверх состояния: применяются целиком или не применяются вовсе."""

    def __init__(self, bal, nonce):
        self._bal, self._nonce, self.b, self.n = bal, nonce, {}, {}

    def bal(self, a):
        return self.b[a] if a in self.b else self._bal.get(a, 0)

    def nonce(self, a):
        return self.n[a] if a in self.n else self._nonce.get(a, 0)

    def set_bal(self, a, v):
        self.b[a] = v

    def set_nonce(self, a, v):
        self.n[a] = v

    def commit(self):
        undo = {"b": {a: self._bal.get(a) for a in self.b}, "n": {a: self._nonce.get(a) for a in self.n}}
        self._bal.update(self.b)
        self._nonce.update(self.n)
        return undo


_SIG_OK = {}


def _verify_cached(tx, chain_id):
    key = txid(tx)
    if _SIG_OK.get(key) == chain_id:
        return True
    pub = bytes.fromhex(tx["from_pub"])
    ok = decompress(pub) is not None and verify(
        pub, tx_digest(chain_id, tx["from_pub"], tx["to"], tx["amount"], tx["fee"], tx["nonce"]), tx["sig"])
    if ok:
        if len(_SIG_OK) > 50_000:
            _SIG_OK.clear()
        _SIG_OK[key] = chain_id
    return ok


class Chain:
    def __init__(self, genesis):
        self.params = Params(genesis)
        gb = self.params.block
        self.blocks = [gb]
        self.undos = [None]
        self.work = [block_work(gb)]
        self.bal = {self.params.founder: FOUNDER_ALLOC}
        self.nonce = {}
        self.txindex = {txid(gb["txs"][0]): 0}
        self.addr_txs = {self.params.founder: [(0, txid(gb["txs"][0]))]}
        self.hindex = {gb["hash"]: 0}

    # --- чтение
    @property
    def height(self):
        return len(self.blocks) - 1

    @property
    def tip(self):
        return self.blocks[-1]

    def mtp(self, h):
        times = sorted(b["time"] for b in self.blocks[max(0, h - MTP_WINDOW):h])
        return times[len(times) // 2]

    def expected_target(self, h):
        prev = self.blocks[h - 1]
        ptarget = int(prev["target"], 16)
        if h % RETARGET_INTERVAL != 0:
            return ptarget
        span_target = RETARGET_INTERVAL * BLOCK_TIME
        span = prev["time"] - self.blocks[h - RETARGET_INTERVAL]["time"]
        span = max(span_target // 4, min(span_target * 4, span))
        return max(1, min(ptarget * span // span_target, self.params.pow_limit))

    def account(self, addr, t=None):
        t = int(time.time()) if t is None else t
        locked = self.params.locked(addr, t)
        bal = self.bal.get(addr, 0)
        return {"address": addr, "balance": bal, "nonce": self.nonce.get(addr, 0), "locked": min(locked, bal),
                "spendable": max(0, bal - locked)}

    # --- проверка и применение перевода
    def apply_transfer(self, tx, ov, t):
        check_transfer_schema(tx)
        sender = tx_sender(tx)
        if tx["to"] == sender:
            raise ConsensusError("нельзя отправить самому себе")
        if not _verify_cached(tx, self.params.chain_id):
            raise ConsensusError("неверная подпись")
        n = ov.nonce(sender)
        if tx["nonce"] != n:
            raise ConsensusError("неверный nonce (ожидался %d)" % n)
        bal, cost = ov.bal(sender), tx["amount"] + tx["fee"]
        if cost > bal:
            raise ConsensusError("недостаточно средств")
        after = bal - cost
        if after < self.params.locked(sender, t):
            raise ConsensusError("часть средств заморожена (vesting основателя)")
        ov.set_bal(sender, after)
        ov.set_nonce(sender, n + 1)
        ov.set_bal(tx["to"], ov.bal(tx["to"]) + tx["amount"])

    # --- добавление блока в конец цепочки
    def add_block(self, block, check_future=True, now=None):
        check_block_schema(block)
        prev, h = self.tip, len(self.blocks)
        if block["height"] != h:
            raise ConsensusError("неверная высота блока")
        if block["prev"] != prev["hash"]:
            raise ConsensusError("блок не продолжает текущую цепочку")
        if block["hash"] != block_hash(block):
            raise ConsensusError("хеш блока не совпадает с содержимым")
        target = self.expected_target(h)
        if int(block["target"], 16) != target:
            raise ConsensusError("неверная сложность блока")
        if int(block["hash"], 16) > target:
            raise ConsensusError("proof-of-work не выполнен")
        if block["time"] <= self.mtp(h):
            raise ConsensusError("время блока не больше медианы предыдущих")
        if check_future and block["time"] > (time.time() if now is None else now) + MAX_FUTURE_DRIFT:
            raise ConsensusError("время блока слишком далеко в будущем")
        txs = block["txs"]
        for t in txs[1:]:
            check_transfer_schema(t)
        check_coinbase_schema(txs[0])
        ids = [txid(t) for t in txs]
        if len(set(ids)) != len(ids):
            raise ConsensusError("повторяющиеся транзакции в блоке")
        if merkle_root(ids) != block["merkle"]:
            raise ConsensusError("Merkle-корень не совпадает")
        ov, fees = Overlay(self.bal, self.nonce), 0
        for t in txs[1:]:
            self.apply_transfer(t, ov, block["time"])
            fees += t["fee"]
        cb = txs[0]
        if cb["height"] != h:
            raise ConsensusError("высота в coinbase не совпадает")
        if cb["amount"] > block_reward(h) + fees:
            raise ConsensusError("награда майнера больше допустимой")
        ov.set_bal(cb["to"], ov.bal(cb["to"]) + cb["amount"])
        undo = ov.commit()
        for t, tid in zip(txs, ids):
            self.txindex[tid] = h
            parties = [t["to"]] if t["type"] == "coinbase" else list(dict.fromkeys([tx_sender(t), t["to"]]))
            for a in parties:
                self.addr_txs.setdefault(a, []).append((h, tid))
        self.blocks.append(block)
        self.undos.append(undo)
        self.work.append(self.work[-1] + block_work(block))
        self.hindex[block["hash"]] = h

    # --- откат
    def rollback_to(self, height):
        while len(self.blocks) - 1 > height:
            block, undo = self.blocks.pop(), self.undos.pop()
            self.work.pop()
            self.hindex.pop(block["hash"], None)
            for a, old in undo["b"].items():
                if old is None:
                    self.bal.pop(a, None)
                else:
                    self.bal[a] = old
            for a, old in undo["n"].items():
                if old is None:
                    self.nonce.pop(a, None)
                else:
                    self.nonce[a] = old
            for t in reversed(block["txs"]):
                tid = txid(t)
                self.txindex.pop(tid, None)
                parties = [t["to"]] if t["type"] == "coinbase" else list(dict.fromkeys([tx_sender(t), t["to"]]))
                for a in parties:
                    lst = self.addr_txs.get(a)
                    if lst and lst[-1][1] == tid:
                        lst.pop()
                        if not lst:
                            del self.addr_txs[a]

    def reorg(self, fork_height, new_blocks, check_future=True, now=None):
        """Переключиться на другую ветку, если у неё больше суммарной работы. При ошибке цепочка не меняется."""
        if not 0 <= fork_height <= self.height:
            raise ConsensusError("неверная точка ветвления")
        old_work, old_tail = self.work[-1], self.blocks[fork_height + 1:]
        self.rollback_to(fork_height)
        try:
            for b in new_blocks:
                self.add_block(b, check_future, now)
            if self.work[-1] <= old_work:
                raise ConsensusError("у новой ветки не больше работы, чем у текущей")
        except ConsensusError:
            self.rollback_to(fork_height)
            for b in old_tail:
                self.add_block(b, check_future=False)
            raise
        return old_tail
