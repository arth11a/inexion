/*
 * inxscan.c: быстрый перебор nonce для майнера INEXION (двойной SHA-256, как в core.py).
 *
 *   inxscan PREFIX_HEX TARGET_HEX START COUNT THREADS   -> печатает "FOUND <nonce>" или "NONE"
 *   inxscan --selftest                                  -> проверка хеша и замер скорости
 *   inxscan --impl                                      -> какая реализация SHA-256 будет использована
 *
 * Хешируется:  sha256d(prefix || десятичная_запись_nonce), как в core.block_hash().
 * Реализации SHA-256, выбираются при запуске:
 *   - x86-64: аппаратные инструкции SHA-NI (Intel с Ice Lake, AMD с Zen), если процессор их поддерживает;
 *   - ARMv8 (Apple Silicon, ARM-серверы): инструкции SHA2, если программа собрана с ними;
 *   - иначе переносимый C (медленнее, но работает везде).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#if defined(__x86_64__) || defined(__i386__)
#define INX_X86 1
#include <cpuid.h>
#include <immintrin.h>
#endif
#if defined(__ARM_FEATURE_SHA2)
#define INX_ARM 1
#include <arm_neon.h>
#endif

static const uint32_t K[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static const uint32_t IV[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

/* ---- переносимая реализация ---- */
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void compress_c(uint32_t st[8], const uint8_t blk[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)blk[4*i] << 24 | (uint32_t)blk[4*i+1] << 16 | (uint32_t)blk[4*i+2] << 8 | blk[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = st[0]; b = st[1]; c = st[2]; d = st[3]; e = st[4]; f = st[5]; g = st[6]; h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

/* ---- ARMv8 SHA2 ---- */
#ifdef INX_ARM
static void compress_arm(uint32_t st[8], const uint8_t blk[64]) {
    uint32x4_t abcd = vld1q_u32(st), efgh = vld1q_u32(st + 4), s0 = abcd, s1 = efgh, m[4], wk, tmp;
    for (int i = 0; i < 16; i++) {
        if (i < 4) m[i] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 16 * i)));
        else m[i & 3] = vsha256su1q_u32(vsha256su0q_u32(m[i & 3], m[(i + 1) & 3]), m[(i + 2) & 3], m[(i + 3) & 3]);
        wk = vaddq_u32(m[i & 3], vld1q_u32(&K[4 * i]));
        tmp = abcd;
        abcd = vsha256hq_u32(abcd, efgh, wk);
        efgh = vsha256h2q_u32(efgh, tmp, wk);
    }
    vst1q_u32(st, vaddq_u32(abcd, s0));
    vst1q_u32(st + 4, vaddq_u32(efgh, s1));
}
#endif

/* ---- x86 SHA-NI ---- */
#ifdef INX_X86
__attribute__((target("sha,sse4.1,ssse3")))
static void compress_shani(uint32_t state[8], const uint8_t data[64]) {
    __m128i STATE0, STATE1, MSG, TMP, m[4], ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    TMP = _mm_loadu_si128((const __m128i *)&state[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);
    TMP = _mm_shuffle_epi32(TMP, 0xB1);              /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);        /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);        /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);     /* CDGH */
    ABEF_SAVE = STATE0; CDGH_SAVE = STATE1;
    for (int i = 0; i < 16; i++) {
        if (i < 4) m[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 16 * i)), MASK);
        else {
            __m128i t = _mm_sha256msg1_epu32(m[i & 3], m[(i + 1) & 3]);
            t = _mm_add_epi32(t, _mm_alignr_epi8(m[(i + 3) & 3], m[(i + 2) & 3], 4));
            m[i & 3] = _mm_sha256msg2_epu32(t, m[(i + 3) & 3]);
        }
        MSG = _mm_add_epi32(m[i & 3], _mm_loadu_si128((const __m128i *)&K[4 * i]));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    }
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
    TMP = _mm_shuffle_epi32(STATE0, 0x1B);           /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);        /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);     /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);        /* HGFE */
    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

static int cpu_has_shani(void) {
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    if (!(c & (1u << 19)) || !(c & (1u << 9))) return 0;          /* SSE4.1, SSSE3 */
    if (__get_cpuid_max(0, 0) < 7) return 0;
    __cpuid_count(7, 0, a, b, c, d);
    return (b >> 29) & 1;                                         /* SHA */
}
#endif

static void (*compress)(uint32_t[8], const uint8_t[64]) = compress_c;
static const char *impl_name = "portable C";
static void init_impl(void) {
#ifdef INX_ARM
    compress = compress_arm; impl_name = "ARMv8 SHA2";
#elif defined(INX_X86)
    if (cpu_has_shani()) { compress = compress_shani; impl_name = "x86 SHA-NI"; }
#endif
    const char *force = getenv("INXSCAN_FORCE_PORTABLE");        /* для проверки: принудительно переносимый вариант */
    if (force && *force == '1') { compress = compress_c; impl_name = "portable C (forced)"; }
}

static void put_be(uint8_t *o, const uint32_t st[8]) {
    for (int i = 0; i < 8; i++) { o[4*i] = st[i] >> 24; o[4*i+1] = st[i] >> 16; o[4*i+2] = st[i] >> 8; o[4*i+3] = st[i]; }
}

/* ---- общий контекст ---- */
typedef struct {
    uint32_t mid[8];          /* состояние после целых 64-байтных блоков префикса */
    uint8_t tail0[64];        /* остаток префикса (< 64 байт) */
    size_t tail_len, plen;
    uint8_t target[32];
    uint64_t start, count;
    int nthreads;
} Ctx;

static volatile int g_done = 0;
static volatile uint64_t g_found = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static void prepare(Ctx *c, const uint8_t *prefix, size_t plen) {
    memcpy(c->mid, IV, 32);
    size_t full = plen / 64;
    for (size_t i = 0; i < full; i++) compress(c->mid, prefix + 64 * i);
    c->tail_len = plen - 64 * full;
    memset(c->tail0, 0, 64);
    memcpy(c->tail0, prefix + 64 * full, c->tail_len);
    c->plen = plen;
}

/* sha256d(prefix || decimal(nonce)) -> out[32] */
static void hash_nonce(const Ctx *c, uint64_t nonce, uint8_t out[32]) {
    char dig[24]; int nd = 0;
    uint64_t v = nonce;
    do { dig[nd++] = '0' + (v % 10); v /= 10; } while (v);
    uint8_t buf[128]; memset(buf, 0, 128);
    memcpy(buf, c->tail0, c->tail_len);
    for (int i = 0; i < nd; i++) buf[c->tail_len + i] = dig[nd - 1 - i];
    size_t used = c->tail_len + nd;
    buf[used] = 0x80;
    size_t nblk = (used + 9 <= 64) ? 1 : 2;
    uint64_t bits = (uint64_t)(c->plen + nd) * 8;
    for (int i = 0; i < 8; i++) buf[64 * nblk - 1 - i] = bits >> (8 * i);
    uint32_t st[8]; memcpy(st, c->mid, 32);
    compress(st, buf);
    if (nblk == 2) compress(st, buf + 64);
    uint8_t b2[64]; memset(b2, 0, 64);
    put_be(b2, st);
    b2[32] = 0x80; b2[62] = 0x01; b2[63] = 0x00;       /* длина 256 бит = 0x0100 */
    uint32_t s2[8]; memcpy(s2, IV, 32);
    compress(s2, b2);
    put_be(out, s2);
}

static void *worker(void *arg) {
    void **a = arg; const Ctx *c = a[0]; int id = (int)(intptr_t)a[1];
    uint8_t h[32];
    for (uint64_t i = id; i < c->count; i += c->nthreads) {
        if ((i & 0x3ff) == 0 && g_done) return NULL;
        uint64_t n = c->start + i;
        hash_nonce(c, n, h);
        if (memcmp(h, c->target, 32) <= 0) {
            pthread_mutex_lock(&g_mu);
            if (!g_done) { g_done = 1; g_found = n; }
            pthread_mutex_unlock(&g_mu);
            return NULL;
        }
    }
    return NULL;
}

static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
static int unhex(const char *s, uint8_t *o, size_t max) {
    size_t n = strlen(s); if (n % 2 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) { int a = hexval(s[2*i]), b = hexval(s[2*i+1]); if (a < 0 || b < 0) return -1; o[i] = a << 4 | b; }
    return (int)(n / 2);
}

static int run(Ctx *c, int nthreads, uint64_t *found) {
    pthread_t th[64]; void *args[64][2];
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 64) nthreads = 64;
    c->nthreads = nthreads; g_done = 0;
    for (int i = 0; i < nthreads; i++) { args[i][0] = c; args[i][1] = (void *)(intptr_t)i; pthread_create(&th[i], NULL, worker, args[i]); }
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    if (g_done) { *found = g_found; return 1; }
    return 0;
}

static int selftest(void) {
    /* sha256d("abc" + "12345") = эталон, посчитан hashlib */
    Ctx c; prepare(&c, (const uint8_t *)"abc", 3);
    uint8_t h[32]; hash_nonce(&c, 12345, h);
    for (int i = 0; i < 32; i++) printf("%02x", h[i]);
    printf("\n");
    /* длинный префикс (как у блока): проверка перехода через границы 64 байт */
    char pre[260]; for (int i = 0; i < 259; i++) pre[i] = 'a' + i % 26; pre[259] = 0;
    for (int len = 190; len < 259; len += 17) {
        prepare(&c, (const uint8_t *)pre, len);
        hash_nonce(&c, 18446744073709551615ULL, h);
        printf("len%d ", len); for (int i = 0; i < 4; i++) printf("%02x", h[i]); printf("\n");
    }
    prepare(&c, (const uint8_t *)pre, 222);
    memset(c.target, 0, 32); c.start = 0; c.count = 20000000ULL;
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t f; run(&c, 4, &f);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double s = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("impl=%s 4 потока: %.1f МХеш/с\n", impl_name, c.count / s / 1e6);
    return 0;
}

int main(int argc, char **argv) {
    init_impl();
    if (argc == 2 && !strcmp(argv[1], "--selftest")) return selftest();
    if (argc == 2 && !strcmp(argv[1], "--impl")) { printf("%s\n", impl_name); return 0; }
    if (argc != 6) { fprintf(stderr, "usage: inxscan PREFIX_HEX TARGET_HEX START COUNT THREADS\n"); return 2; }
    static uint8_t prefix[1024];
    int plen = unhex(argv[1], prefix, sizeof prefix);
    Ctx c; memset(&c, 0, sizeof c);
    if (plen < 0 || unhex(argv[2], c.target, 32) != 32) { fprintf(stderr, "bad hex\n"); return 2; }
    c.start = strtoull(argv[3], NULL, 10); c.count = strtoull(argv[4], NULL, 10);
    prepare(&c, prefix, (size_t)plen);
    uint64_t f;
    if (run(&c, atoi(argv[5]), &f)) printf("FOUND %llu\n", (unsigned long long)f); else printf("NONE\n");
    return 0;
}
