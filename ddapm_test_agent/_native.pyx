# cython: language_level=3, boundscheck=False, wraparound=False, initializedcheck=False, cdivision=True
"""Native fast path for trace payloads: msgpack in, json.dumps-identical fragments out.

transcode_v04() returns None unless it can show that the Python code path (decode_v04 and
Agent._handle_traces, with no checks enabled and logging above INFO) would accept the payload
without raising or logging, and that json.dumps of the decoded traces is byte-identical to the
fragments returned here. None means "use the Python code path".

Keep in sync with trace.py (verify_span, decode_v04, pprint_trace) and with what
Agent._handle_traces does for v0.4 payloads; tests/test_trace_fast_path.py checks parity.
"""

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, int64_t, int8_t, int16_t, int32_t
from libc.string cimport memcpy, memcmp, memset, strlen
from libc.stdlib cimport malloc, realloc, free, strtod, qsort
from libc.stdio cimport snprintf
from libc.math cimport isnan, isinf, signbit, fabs, trunc
from cpython.bytes cimport PyBytes_FromStringAndSize

cdef enum:
    OK = 0
    PY_PATH = 1   # invalid, unusual, or not provably identical: let the Python path decide
    NOMEM = 2

cdef enum:
    K_NIL, K_BOOL, K_INT, K_UINT, K_FLOAT, K_STR, K_BIN, K_ARR, K_MAP

cdef enum:
    MAX_DEPTH = 256

cdef enum:
    MAP_ANY = 0
    MAP_STR_VALUES = 1    # meta
    MAP_NUM_VALUES = 2    # metrics

cdef struct Val:
    int kind
    int64_t i
    uint64_t u
    double f
    const uint8_t* s
    uint32_t n

cdef struct KeyRef:
    const uint8_t* s
    uint32_t n

cdef struct Id:
    uint64_t u
    uint8_t neg

cdef struct Ctx:
    const uint8_t* p
    const uint8_t* end
    uint8_t* out
    size_t len
    size_t cap
    KeyRef* keys      # stack of map keys, for duplicate detection
    size_t nkeys
    size_t keys_cap
    Id* ids           # span_ids of the current chunk
    size_t nids
    size_t ids_cap
    Id* run_tid
    size_t* run_start
    size_t* run_end
    size_t nruns
    size_t runs_cap


# ---- output -------------------------------------------------------------------------------
cdef int grow(Ctx* c, size_t n) noexcept nogil:
    cdef size_t want = c.len + n
    cdef size_t cap = c.cap * 2
    if cap < want + 4096:
        cap = want + 4096
    cdef uint8_t* out = <uint8_t*>realloc(c.out, cap)
    if out == NULL:
        return NOMEM
    c.out = out
    c.cap = cap
    return OK


cdef inline int reserve(Ctx* c, size_t n) noexcept nogil:
    if c.len + n > c.cap:
        return grow(c, n)
    return OK


cdef inline int put(Ctx* c, const char* s, size_t n) noexcept nogil:
    if reserve(c, n) != OK:
        return NOMEM
    memcpy(c.out + c.len, s, n)
    c.len += n
    return OK


cdef inline int putc(Ctx* c, char ch) noexcept nogil:
    if reserve(c, 1) != OK:
        return NOMEM
    c.out[c.len] = <uint8_t>ch
    c.len += 1
    return OK


# ---- input --------------------------------------------------------------------------------
cdef inline uint16_t be16(const uint8_t* p) noexcept nogil:
    return (<uint16_t>p[0] << 8) | p[1]


cdef inline uint32_t be32(const uint8_t* p) noexcept nogil:
    return (<uint32_t>p[0] << 24) | (<uint32_t>p[1] << 16) | (<uint32_t>p[2] << 8) | p[3]


cdef inline uint64_t be64(const uint8_t* p) noexcept nogil:
    return (<uint64_t>be32(p) << 32) | be32(p + 4)


cdef int read_val(Ctx* c, Val* v) noexcept nogil:
    """Consume one msgpack header (and the bytes of str/bin). Ext and reserved types -> PY_PATH."""
    if c.p >= c.end:
        return PY_PATH
    cdef uint8_t b = c.p[0]
    cdef size_t avail
    cdef uint32_t n
    cdef uint32_t f32bits
    cdef float f32
    cdef uint64_t f64bits
    cdef double f64
    c.p += 1
    avail = c.end - c.p
    if b <= 0x7F:
        v.kind = K_UINT; v.u = b; return OK
    if b >= 0xE0:
        v.kind = K_INT; v.i = <int8_t>b; return OK
    if b <= 0x8F:
        v.kind = K_MAP; v.n = b & 0x0F; return OK
    if b <= 0x9F:
        v.kind = K_ARR; v.n = b & 0x0F; return OK
    if b <= 0xBF:
        n = b & 0x1F
        v.kind = K_STR
    elif b == 0xC0:
        v.kind = K_NIL; return OK
    elif b == 0xC2 or b == 0xC3:
        v.kind = K_BOOL; v.u = b - 0xC2; return OK
    elif b == 0xC4 or b == 0xD9:
        if avail < 1: return PY_PATH
        n = c.p[0]; c.p += 1; avail -= 1
        v.kind = K_BIN if b == 0xC4 else K_STR
    elif b == 0xC5 or b == 0xDA:
        if avail < 2: return PY_PATH
        n = be16(c.p); c.p += 2; avail -= 2
        v.kind = K_BIN if b == 0xC5 else K_STR
    elif b == 0xC6 or b == 0xDB:
        if avail < 4: return PY_PATH
        n = be32(c.p); c.p += 4; avail -= 4
        v.kind = K_BIN if b == 0xC6 else K_STR
    elif b == 0xCA:
        if avail < 4: return PY_PATH
        f32bits = be32(c.p); c.p += 4
        memcpy(&f32, &f32bits, 4)
        v.kind = K_FLOAT; v.f = f32; return OK
    elif b == 0xCB:
        if avail < 8: return PY_PATH
        f64bits = be64(c.p); c.p += 8
        memcpy(&f64, &f64bits, 8)
        v.kind = K_FLOAT; v.f = f64; return OK
    elif b == 0xCC:
        if avail < 1: return PY_PATH
        v.kind = K_UINT; v.u = c.p[0]; c.p += 1; return OK
    elif b == 0xCD:
        if avail < 2: return PY_PATH
        v.kind = K_UINT; v.u = be16(c.p); c.p += 2; return OK
    elif b == 0xCE:
        if avail < 4: return PY_PATH
        v.kind = K_UINT; v.u = be32(c.p); c.p += 4; return OK
    elif b == 0xCF:
        if avail < 8: return PY_PATH
        v.kind = K_UINT; v.u = be64(c.p); c.p += 8; return OK
    elif b == 0xD0:
        if avail < 1: return PY_PATH
        v.kind = K_INT; v.i = <int8_t>c.p[0]; c.p += 1; return OK
    elif b == 0xD1:
        if avail < 2: return PY_PATH
        v.kind = K_INT; v.i = <int16_t>be16(c.p); c.p += 2; return OK
    elif b == 0xD2:
        if avail < 4: return PY_PATH
        v.kind = K_INT; v.i = <int32_t>be32(c.p); c.p += 4; return OK
    elif b == 0xD3:
        if avail < 8: return PY_PATH
        v.kind = K_INT; v.i = <int64_t>be64(c.p); c.p += 8; return OK
    elif b == 0xDC:
        if avail < 2: return PY_PATH
        v.kind = K_ARR; v.n = be16(c.p); c.p += 2; return OK
    elif b == 0xDD:
        if avail < 4: return PY_PATH
        v.kind = K_ARR; v.n = be32(c.p); c.p += 4; return OK
    elif b == 0xDE:
        if avail < 2: return PY_PATH
        v.kind = K_MAP; v.n = be16(c.p); c.p += 2; return OK
    elif b == 0xDF:
        if avail < 4: return PY_PATH
        v.kind = K_MAP; v.n = be32(c.p); c.p += 4; return OK
    else:
        return PY_PATH  # 0xC1 reserved, ext 0xC7-0xC9 / 0xD4-0xD8
    if avail < n:
        return PY_PATH
    v.s = c.p
    v.n = n
    c.p += n
    return OK


cdef inline void as_id(Val* v, Id* out) noexcept nogil:
    # Python int value semantics (bool is int): equal values -> equal Id.
    if v.kind == K_INT and v.i < 0:
        out.u = <uint64_t>v.i
        out.neg = 1
    elif v.kind == K_INT:
        out.u = <uint64_t>v.i
        out.neg = 0
    else:
        out.u = v.u
        out.neg = 0


# ---- json.dumps scalars --------------------------------------------------------------------
cdef inline int put_u64(Ctx* c, uint64_t u) noexcept nogil:
    cdef char buf[24]
    cdef int i = 24
    if u == 0:
        return putc(c, 48)
    while u:
        i -= 1
        buf[i] = <char>(48 + u % 10)
        u //= 10
    return put(c, buf + i, 24 - i)


cdef inline int put_i64(Ctx* c, int64_t i) noexcept nogil:
    if i >= 0:
        return put_u64(c, <uint64_t>i)
    if putc(c, 45) != OK:
        return NOMEM
    return put_u64(c, <uint64_t>0 - <uint64_t>i)


cdef int digits_at(double ax, int p, char* digits, int* decpt) noexcept nogil:
    """Digits of the p-significant-digit decimal float.__repr__ would pick for ax > 0, or 0.

    The nearest p-digit decimal round-trips whenever any does, except at powers of two where
    the interval below is half as wide; there the next decimal up is the only other candidate.
    """
    cdef char buf[40]
    cdef char up[40]
    cdef int n = snprintf(buf, sizeof(buf), b"%.*e", p - 1, ax)
    cdef int e_at = 0
    cdef int k
    cdef int nd = 0
    cdef int exp10
    cdef uint64_t bits
    cdef int carry
    while buf[e_at] != b'e':
        e_at += 1
    exp10 = <int>strtod(buf + e_at + 1, NULL)
    if strtod(buf, NULL) != ax:
        memcpy(&bits, &ax, 8)
        if (bits & ((<uint64_t>1 << 52) - 1)) != 0 or (bits >> 52) <= 1:
            return 0
        memcpy(up, buf, n + 1)
        carry = 1
        k = e_at - 1
        while k >= 0 and carry:
            if up[k] == b'.':
                k -= 1
                continue
            if up[k] == b'9':
                up[k] = b'0'
            else:
                up[k] = up[k] + 1
                carry = 0
            k -= 1
        if carry:
            return 0  # 9.99..e+X rounding up to a new decade is never the shortest
        if strtod(up, NULL) != ax:
            return 0
        memcpy(buf, up, n + 1)
    for k in range(e_at):
        if buf[k] != b'.':
            digits[nd] = buf[k]
            nd += 1
    while nd > 1 and digits[nd - 1] == b'0':
        nd -= 1
    digits[nd] = 0
    decpt[0] = exp10 + 1
    return nd


cdef int put_double(Ctx* c, double v) noexcept nogil:
    """float.__repr__ (what json.dumps writes), with json's NaN/Infinity tokens."""
    cdef char digits[24]
    cdef char buf[48]
    cdef int decpt = 0
    cdef int nd = 0
    cdef int lo = 1
    cdef int hi = 17
    cdef int mid
    cdef int n = 0
    cdef int k
    cdef int e
    cdef double ax
    if isnan(v):
        return put(c, b"NaN", 3)
    if isinf(v):
        return put(c, b"Infinity", 8) if v > 0 else put(c, b"-Infinity", 9)
    if v == 0:
        return put(c, b"-0.0", 4) if signbit(v) else put(c, b"0.0", 3)
    ax = fabs(v)
    if ax < 1e16 and trunc(v) == v:
        if put_i64(c, <int64_t>v) != OK:
            return NOMEM
        return put(c, b".0", 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if digits_at(ax, mid, digits, &decpt):
            hi = mid
        else:
            lo = mid + 1
    nd = digits_at(ax, lo, digits, &decpt)
    if nd == 0:
        return PY_PATH
    if v < 0:
        buf[n] = b'-'; n += 1
    if decpt <= -4 or decpt > 16:
        buf[n] = digits[0]; n += 1
        if nd > 1:
            buf[n] = b'.'; n += 1
            for k in range(1, nd):
                buf[n] = digits[k]; n += 1
        e = decpt - 1
        n += snprintf(buf + n, sizeof(buf) - n, b"e%c%02d", <int>(45 if e < 0 else 43), <int>(-e if e < 0 else e))
    elif decpt <= 0:
        buf[n] = b'0'; buf[n + 1] = b'.'; n += 2
        for k in range(-decpt):
            buf[n] = b'0'; n += 1
        for k in range(nd):
            buf[n] = digits[k]; n += 1
    elif decpt >= nd:
        for k in range(nd):
            buf[n] = digits[k]; n += 1
        for k in range(decpt - nd):
            buf[n] = b'0'; n += 1
        buf[n] = b'.'; buf[n + 1] = b'0'; n += 2
    else:
        for k in range(decpt):
            buf[n] = digits[k]; n += 1
        buf[n] = b'.'; n += 1
        for k in range(decpt, nd):
            buf[n] = digits[k]; n += 1
    return put(c, buf, n)


cdef inline void hex4(uint8_t* o, uint32_t cp) noexcept nogil:
    cdef const char* hexd = b"0123456789abcdef"
    o[0] = b'\\'
    o[1] = b'u'
    o[2] = hexd[(cp >> 12) & 15]
    o[3] = hexd[(cp >> 8) & 15]
    o[4] = hexd[(cp >> 4) & 15]
    o[5] = hexd[cp & 15]


cdef int put_str(Ctx* c, const uint8_t* s, uint32_t n) noexcept nogil:
    """Strict UTF-8 (msgpack raw=False), written like json.dumps(ensure_ascii=True)."""
    cdef uint32_t i = 0
    cdef uint32_t start
    cdef uint8_t b
    cdef uint32_t need
    cdef uint32_t cp
    cdef uint32_t k
    cdef uint8_t* o
    if reserve(c, <size_t>n * 6 + 2) != OK:
        return NOMEM
    c.out[c.len] = b'"'
    c.len += 1
    while i < n:
        start = i
        while i < n and s[i] >= 0x20 and s[i] <= 0x7E and s[i] != b'"' and s[i] != b'\\':
            i += 1
        if i > start:
            memcpy(c.out + c.len, s + start, i - start)
            c.len += i - start
        if i >= n:
            break
        b = s[i]
        o = c.out + c.len
        if b < 0x80:
            o[0] = b'\\'
            if b == b'"' or b == b'\\':
                o[1] = b; c.len += 2
            elif b == 0x08:
                o[1] = b'b'; c.len += 2
            elif b == 0x0C:
                o[1] = b'f'; c.len += 2
            elif b == 0x0A:
                o[1] = b'n'; c.len += 2
            elif b == 0x0D:
                o[1] = b'r'; c.len += 2
            elif b == 0x09:
                o[1] = b't'; c.len += 2
            else:
                hex4(o, b); c.len += 6
            i += 1
            continue
        if 0xC2 <= b <= 0xDF:
            need = 1; cp = b & 0x1F
        elif 0xE0 <= b <= 0xEF:
            need = 2; cp = b & 0x0F
        elif 0xF0 <= b <= 0xF4:
            need = 3; cp = b & 0x07
        else:
            return PY_PATH
        if i + need >= n:
            return PY_PATH
        for k in range(1, need + 1):
            if (s[i + k] & 0xC0) != 0x80:
                return PY_PATH
            cp = (cp << 6) | (s[i + k] & 0x3F)
        if need == 2 and (cp < 0x800 or 0xD800 <= cp <= 0xDFFF):
            return PY_PATH
        if need == 3 and (cp < 0x10000 or cp > 0x10FFFF):
            return PY_PATH
        if cp >= 0x10000:
            cp -= 0x10000
            hex4(o, 0xD800 | (cp >> 10))
            hex4(o + 6, 0xDC00 | (cp & 0x3FF))
            c.len += 12
        else:
            hex4(o, cp)
            c.len += 6
        i += need + 1
    c.out[c.len] = b'"'
    c.len += 1
    return OK


# ---- duplicate keys -----------------------------------------------------------------------
cdef int keycmp(const void* a, const void* b) noexcept nogil:
    cdef const KeyRef* x = <const KeyRef*>a
    cdef const KeyRef* y = <const KeyRef*>b
    if x.n != y.n:
        return -1 if x.n < y.n else 1
    return memcmp(x.s, y.s, x.n)


cdef int push_key(Ctx* c, const uint8_t* s, uint32_t n) noexcept nogil:
    cdef size_t cap
    cdef KeyRef* keys
    if c.nkeys == c.keys_cap:
        cap = c.keys_cap * 2 if c.keys_cap else 256
        keys = <KeyRef*>realloc(c.keys, cap * sizeof(KeyRef))
        if keys == NULL:
            return NOMEM
        c.keys = keys
        c.keys_cap = cap
    c.keys[c.nkeys].s = s
    c.keys[c.nkeys].n = n
    c.nkeys += 1
    return OK


cdef int pop_keys_unique(Ctx* c, size_t base) noexcept nogil:
    """A Python dict keeps one entry per key, so json.dumps of it differs from the msgpack map."""
    cdef size_t n = c.nkeys - base
    cdef size_t a
    cdef size_t b
    cdef KeyRef* k = c.keys + base
    if n <= 16:
        for a in range(n):
            for b in range(a + 1, n):
                if k[a].n == k[b].n and memcmp(k[a].s, k[b].s, k[a].n) == 0:
                    return PY_PATH
    else:
        qsort(k, n, sizeof(KeyRef), keycmp)
        for a in range(1, n):
            if keycmp(&k[a - 1], &k[a]) == 0:
                return PY_PATH
    c.nkeys = base
    return OK


# ---- containers ---------------------------------------------------------------------------
cdef int emit_any(Ctx* c, Val* v, int depth) noexcept nogil:
    cdef uint32_t j
    cdef Val x
    cdef int rc
    if depth > MAX_DEPTH:
        return PY_PATH
    if v.kind == K_NIL:
        return put(c, b"null", 4)
    if v.kind == K_BOOL:
        return put(c, b"true", 4) if v.u else put(c, b"false", 5)
    if v.kind == K_UINT:
        return put_u64(c, v.u)
    if v.kind == K_INT:
        return put_i64(c, v.i)
    if v.kind == K_FLOAT:
        return put_double(c, v.f)
    if v.kind == K_STR:
        return put_str(c, v.s, v.n)
    if v.kind == K_ARR:
        if putc(c, b'[') != OK:
            return NOMEM
        for j in range(v.n):
            if j and put(c, b", ", 2) != OK:
                return NOMEM
            rc = read_val(c, &x)
            if rc == OK:
                rc = emit_any(c, &x, depth + 1)
            if rc != OK:
                return rc
        return putc(c, b']')
    if v.kind == K_MAP:
        return emit_map(c, v.n, depth, MAP_ANY)
    return PY_PATH  # bytes are not JSON serializable


cdef int emit_map(Ctx* c, uint32_t n, int depth, int mode) noexcept nogil:
    cdef Val k
    cdef Val x
    cdef uint32_t j
    cdef int rc
    cdef size_t base = c.nkeys
    if depth > MAX_DEPTH:
        return PY_PATH
    if putc(c, b'{') != OK:
        return NOMEM
    for j in range(n):
        rc = read_val(c, &k)
        if rc != OK:
            return rc
        if k.kind != K_STR:
            return PY_PATH
        if push_key(c, k.s, k.n) != OK:
            return NOMEM
        if j and put(c, b", ", 2) != OK:
            return NOMEM
        rc = put_str(c, k.s, k.n)
        if rc != OK:
            return rc
        if put(c, b": ", 2) != OK:
            return NOMEM
        rc = read_val(c, &x)
        if rc != OK:
            return rc
        if mode == MAP_STR_VALUES and x.kind != K_STR:
            return PY_PATH
        if mode == MAP_NUM_VALUES and not (x.kind == K_INT or x.kind == K_UINT or x.kind == K_BOOL or x.kind == K_FLOAT):
            return PY_PATH
        rc = emit_any(c, &x, depth + 1)
        if rc != OK:
            return rc
    rc = pop_keys_unique(c, base)
    if rc != OK:
        return rc
    return putc(c, b'}')


cdef int emit_meta_struct(Ctx* c, uint32_t n) noexcept nogil:
    cdef Val k
    cdef Val x
    cdef Val inner
    cdef uint32_t j
    cdef int rc
    cdef size_t base = c.nkeys
    cdef const uint8_t* save_p
    cdef const uint8_t* save_end
    if putc(c, b'{') != OK:
        return NOMEM
    for j in range(n):
        rc = read_val(c, &k)
        if rc != OK:
            return rc
        if k.kind != K_STR:
            return PY_PATH
        # _llmobs makes the Python handler synthesize an EVP request.
        if k.n == 7 and memcmp(k.s, b"_llmobs", 7) == 0:
            return PY_PATH
        if push_key(c, k.s, k.n) != OK:
            return NOMEM
        if j and put(c, b", ", 2) != OK:
            return NOMEM
        rc = put_str(c, k.s, k.n)
        if rc != OK:
            return rc
        if put(c, b": ", 2) != OK:
            return NOMEM
        rc = read_val(c, &x)
        if rc != OK:
            return rc
        if x.kind != K_BIN:
            return PY_PATH
        save_p = c.p
        save_end = c.end
        c.p = x.s
        c.end = x.s + x.n
        rc = read_val(c, &inner)
        if rc == OK and inner.kind != K_MAP:
            rc = PY_PATH
        if rc == OK:
            rc = emit_map(c, inner.n, 2, MAP_ANY)
        if rc == OK and c.p != c.end:
            rc = PY_PATH  # msgpack.unpackb raises ExtraData
        c.p = save_p
        c.end = save_end
        if rc != OK:
            return rc
    rc = pop_keys_unique(c, base)
    if rc != OK:
        return rc
    return putc(c, b'}')


# ---- spans --------------------------------------------------------------------------------
cdef inline bint is_int(Val* v) noexcept nogil:
    return v.kind == K_INT or v.kind == K_UINT or v.kind == K_BOOL


cdef inline bint key_is(Val* k, const char* name, uint32_t n) noexcept nogil:
    return k.n == n and memcmp(k.s, name, n) == 0


cdef int push_id(Ctx* c, Id* id) noexcept nogil:
    cdef size_t cap
    cdef Id* ids
    if c.nids == c.ids_cap:
        cap = c.ids_cap * 2 if c.ids_cap else 4096
        ids = <Id*>realloc(c.ids, cap * sizeof(Id))
        if ids == NULL:
            return NOMEM
        c.ids = ids
        c.ids_cap = cap
    c.ids[c.nids] = id[0]
    c.nids += 1
    return OK


cdef int idcmp(const void* a, const void* b) noexcept nogil:
    cdef const Id* x = <const Id*>a
    cdef const Id* y = <const Id*>b
    if x.neg != y.neg:
        return -1 if x.neg < y.neg else 1
    if x.u != y.u:
        return -1 if x.u < y.u else 1
    return 0


cdef int add_run(Ctx* c, Id* tid, size_t start, size_t end) noexcept nogil:
    cdef size_t cap
    if c.nruns == c.runs_cap:
        cap = c.runs_cap * 2 if c.runs_cap else 16
        c.run_tid = <Id*>realloc(c.run_tid, cap * sizeof(Id))
        c.run_start = <size_t*>realloc(c.run_start, cap * sizeof(size_t))
        c.run_end = <size_t*>realloc(c.run_end, cap * sizeof(size_t))
        if c.run_tid == NULL or c.run_start == NULL or c.run_end == NULL:
            return NOMEM
        c.runs_cap = cap
    c.run_tid[c.nruns] = tid[0]
    c.run_start[c.nruns] = start
    c.run_end[c.nruns] = end
    c.nruns += 1
    return OK


cdef int emit_span(Ctx* c) noexcept nogil:
    cdef Val sp
    cdef Val k
    cdef Val x
    cdef uint32_t j
    cdef int rc
    cdef bint have_span_id = False
    cdef bint have_trace_id = False
    cdef bint have_name = False
    cdef Id tid
    cdef Id sid
    cdef size_t base = c.nkeys
    cdef size_t sep
    cdef size_t start
    rc = read_val(c, &sp)
    if rc != OK:
        return rc
    if sp.kind != K_MAP:
        return PY_PATH
    # Two separator bytes are reserved before each span: ", " when it continues the previous
    # span's trace_id run, unused otherwise.
    sep = c.len
    if put(c, b", ", 2) != OK:
        return NOMEM
    start = c.len
    if putc(c, b'{') != OK:
        return NOMEM
    for j in range(sp.n):
        rc = read_val(c, &k)
        if rc != OK:
            return rc
        if k.kind != K_STR:
            return PY_PATH
        if push_key(c, k.s, k.n) != OK:
            return NOMEM
        if j and put(c, b", ", 2) != OK:
            return NOMEM
        rc = put_str(c, k.s, k.n)
        if rc != OK:
            return rc
        if put(c, b": ", 2) != OK:
            return NOMEM
        rc = read_val(c, &x)
        if rc != OK:
            return rc
        # verify_span type rules; anything that breaks them is the Python path's to reject.
        if key_is(&k, b"span_id", 7):
            if not is_int(&x):
                return PY_PATH
            have_span_id = True
            as_id(&x, &sid)
            rc = emit_any(c, &x, 1)
        elif key_is(&k, b"trace_id", 8):
            if not is_int(&x):
                return PY_PATH
            have_trace_id = True
            as_id(&x, &tid)
            rc = emit_any(c, &x, 1)
        elif key_is(&k, b"name", 4):
            if x.kind != K_STR:
                return PY_PATH
            have_name = True
            rc = put_str(c, x.s, x.n)
        elif key_is(&k, b"resource", 8) or key_is(&k, b"service", 7) or key_is(&k, b"type", 4):
            if x.kind != K_STR and x.kind != K_NIL:
                return PY_PATH
            rc = emit_any(c, &x, 1)
        elif key_is(&k, b"parent_id", 9):
            if not is_int(&x) and x.kind != K_NIL:
                return PY_PATH
            rc = emit_any(c, &x, 1)
        elif key_is(&k, b"error", 5):
            if not is_int(&x):
                return PY_PATH
            rc = emit_any(c, &x, 1)
        elif key_is(&k, b"start", 5):
            # pprint_trace sorts siblings by start: only numbers are always comparable.
            if not (is_int(&x) or x.kind == K_FLOAT):
                return PY_PATH
            rc = emit_any(c, &x, 1)
        elif key_is(&k, b"meta", 4):
            if x.kind != K_MAP:
                return PY_PATH
            rc = emit_map(c, x.n, 1, MAP_STR_VALUES)
        elif key_is(&k, b"metrics", 7):
            if x.kind != K_MAP:
                return PY_PATH
            rc = emit_map(c, x.n, 1, MAP_NUM_VALUES)
        elif key_is(&k, b"meta_struct", 11):
            if x.kind != K_MAP:
                return PY_PATH
            rc = emit_meta_struct(c, x.n)
        elif key_is(&k, b"span_links", 10) or key_is(&k, b"span_events", 11):
            return PY_PATH
        else:
            rc = emit_any(c, &x, 1)
        if rc != OK:
            return rc
    rc = pop_keys_unique(c, base)
    if rc != OK:
        return rc
    if not (have_span_id and have_trace_id and have_name):
        return PY_PATH
    if push_id(c, &sid) != OK:
        return NOMEM
    if putc(c, b'}') != OK:
        return NOMEM
    if c.nruns and idcmp(&c.run_tid[c.nruns - 1], &tid) == 0 and c.run_end[c.nruns - 1] == sep:
        c.run_end[c.nruns - 1] = c.len
        return OK
    return add_run(c, &tid, start, c.len)


cdef int check_chunk_ids(Ctx* c) noexcept nogil:
    """pprint_trace walks span_id -> children; a 0 or repeated span_id can make it loop forever."""
    cdef size_t i
    for i in range(c.nids):
        if c.ids[i].u == 0:
            return PY_PATH
    if c.nids > 1:
        qsort(c.ids, c.nids, sizeof(Id), idcmp)
        for i in range(1, c.nids):
            if idcmp(&c.ids[i - 1], &c.ids[i]) == 0:
                return PY_PATH
    c.nids = 0
    return OK


cdef int transcode(Ctx* c) noexcept nogil:
    cdef Val top
    cdef Val tr
    cdef uint32_t i
    cdef uint32_t j
    cdef int rc
    rc = read_val(c, &top)
    if rc != OK:
        return rc
    if top.kind != K_ARR:
        return PY_PATH
    for i in range(top.n):
        rc = read_val(c, &tr)
        if rc != OK:
            return rc
        if tr.kind != K_ARR:
            return PY_PATH
        for j in range(tr.n):
            rc = emit_span(c)
            if rc != OK:
                return rc
        rc = check_chunk_ids(c)
        if rc != OK:
            return rc
    if c.p != c.end:
        return PY_PATH  # the Python path logs ExtraData and still answers 200
    return OK


cdef void ctx_free(Ctx* c) noexcept nogil:
    free(c.out)
    free(c.keys)
    free(c.ids)
    free(c.run_tid)
    free(c.run_start)
    free(c.run_end)


cdef void ctx_init(Ctx* c, size_t cap) noexcept nogil:
    c.cap = cap
    c.out = <uint8_t*>malloc(cap)
    c.len = 0
    c.keys = NULL
    c.nkeys = 0
    c.keys_cap = 0
    c.ids = NULL
    c.nids = 0
    c.ids_cap = 0
    c.run_tid = NULL
    c.run_start = NULL
    c.run_end = NULL
    c.nruns = 0
    c.runs_cap = 0


cdef object _result(Ctx* c, int rc):
    cdef size_t i
    if rc == NOMEM:
        raise MemoryError()
    if rc != OK:
        return None
    body = PyBytes_FromStringAndSize(<char*>c.out, c.len)
    runs = []
    for i in range(c.nruns):
        if c.run_tid[i].neg:
            runs.append((<int64_t>c.run_tid[i].u, c.run_start[i], c.run_end[i]))
        else:
            runs.append((c.run_tid[i].u, c.run_start[i], c.run_end[i]))
    return body, runs


def transcode_v04(const uint8_t[::1] data not None):
    """Return (json_bytes, [(trace_id, start, end), ...]) or None for the Python path.

    body[start:end] is ", ".join(json.dumps(span) for span in run): a run of consecutive spans
    with the same trace_id, exactly as json.dumps renders them inside the session response.
    """
    cdef Ctx c
    cdef int rc
    if data.shape[0] == 0:
        return None
    ctx_init(&c, <size_t>data.shape[0] * 2 + 1024)
    if c.out == NULL:
        raise MemoryError()
    c.p = &data[0]
    c.end = c.p + data.shape[0]
    try:
        with nogil:
            rc = transcode(&c)
        return _result(&c, rc)
    finally:
        ctx_free(&c)


# ---- v1 -----------------------------------------------------------------------------------
# Mirrors trace.decode_v1 / _convert_v1_payload / _convert_v1_chunk / _convert_v1_span /
# _convert_v1_attributes. Parsing builds an intermediate form first because chunk- and
# payload-level fields (which may come after the spans) change every span's meta and metrics.

cdef struct StrRef:
    const uint8_t* s
    uint32_t n

cdef struct KV:
    StrRef key
    Val val           # meta: K_STR; metrics: K_INT / K_UINT / K_FLOAT

cdef enum:
    V1_MAX_FIELDS = 16
    V1_MAX_ATTRS = 512   # upserts are linear; larger maps take the Python path

cdef struct SpanIR:
    uint8_t order[V1_MAX_FIELDS]   # emitted wire keys (1-10) in wire order
    int norder
    StrRef service
    StrRef name
    StrRef resource
    StrRef type_
    StrRef env
    StrRef version
    StrRef component
    Val span_id
    Val parent_id
    Val start
    Val duration
    bint error
    int kind
    bint has_attrs
    bint has_name
    bint has_span_id
    size_t meta_off
    size_t meta_n
    size_t metrics_off
    size_t metrics_n

cdef struct ChunkIR:
    bint has_priority
    Val priority
    StrRef origin
    size_t meta_off
    size_t meta_n
    size_t metrics_off
    size_t metrics_n
    size_t span_off
    size_t span_n
    uint64_t tid_lo
    uint64_t tid_hi
    bint has_sm
    Val sm

cdef struct V1:
    StrRef* tab
    size_t ntab
    size_t tab_cap
    KV* meta
    size_t nmeta
    size_t meta_cap
    KV* metrics
    size_t nmetrics
    size_t metrics_cap
    SpanIR* spans
    size_t nspans
    size_t spans_cap
    ChunkIR* chunks
    size_t nchunks
    size_t chunks_cap
    size_t pmeta_off
    size_t pmeta_n
    size_t pmetrics_off
    size_t pmetrics_n
    KV* scratch
    size_t scratch_cap


cdef int ensure(void** p, size_t* cap, size_t need, size_t elem) noexcept nogil:
    cdef size_t c
    cdef void* q
    if need <= cap[0]:
        return OK
    c = cap[0] * 2 if cap[0] else 64
    while c < need:
        c *= 2
    q = realloc(p[0], c * elem)
    if q == NULL:
        return NOMEM
    p[0] = q
    cap[0] = c
    return OK


cdef bint utf8_ok(const uint8_t* s, uint32_t n) noexcept nogil:
    cdef uint32_t i = 0
    cdef uint32_t need
    cdef uint32_t cp
    cdef uint32_t k
    cdef uint8_t b
    while i < n:
        b = s[i]
        if b < 0x80:
            i += 1
            continue
        if 0xC2 <= b <= 0xDF:
            need = 1; cp = b & 0x1F
        elif 0xE0 <= b <= 0xEF:
            need = 2; cp = b & 0x0F
        elif 0xF0 <= b <= 0xF4:
            need = 3; cp = b & 0x07
        else:
            return False
        if i + need >= n:
            return False
        for k in range(1, need + 1):
            if (s[i + k] & 0xC0) != 0x80:
                return False
            cp = (cp << 6) | (s[i + k] & 0x3F)
        if need == 2 and (cp < 0x800 or 0xD800 <= cp <= 0xDFFF):
            return False
        if need == 3 and (cp < 0x10000 or cp > 0x10FFFF):
            return False
        i += need + 1
    return True


cdef int skip_value(Ctx* c, Val* v, int depth) noexcept nogil:
    """Consume a value msgpack.unpackb would still decode (and validate) but nobody reads."""
    cdef uint32_t j
    cdef Val x
    cdef int rc
    if depth > MAX_DEPTH:
        return PY_PATH
    if v.kind == K_STR:
        return OK if utf8_ok(v.s, v.n) else PY_PATH
    if v.kind == K_ARR or v.kind == K_MAP:
        for j in range(v.n * (2 if v.kind == K_MAP else 1)):
            rc = read_val(c, &x)
            if rc == OK:
                if v.kind == K_MAP and j % 2 == 0 and (x.kind == K_ARR or x.kind == K_MAP):
                    return PY_PATH  # unhashable key
                rc = skip_value(c, &x, depth + 1)
            if rc != OK:
                return rc
    return OK


cdef inline bint as_index(Val* v, uint64_t* out) noexcept nogil:
    # isinstance(x, int) without bool (bool keys/refs would alias 0/1)
    if v.kind == K_UINT:
        out[0] = v.u
        return True
    if v.kind == K_INT and v.i >= 0:
        out[0] = <uint64_t>v.i
        return True
    return False


cdef inline bint is_num(Val* v) noexcept nogil:
    return v.kind == K_INT or v.kind == K_UINT or v.kind == K_FLOAT


cdef int str_ref(Ctx* c, V1* v, StrRef* out) noexcept nogil:
    """_get_and_add_string: an inline str is appended to the table, an int indexes it."""
    cdef Val x
    cdef uint64_t idx
    cdef int rc = read_val(c, &x)
    if rc != OK:
        return rc
    if x.kind == K_STR:
        if not utf8_ok(x.s, x.n):
            return PY_PATH
        if ensure(<void**>&v.tab, &v.tab_cap, v.ntab + 1, sizeof(StrRef)) != OK:
            return NOMEM
        v.tab[v.ntab].s = x.s
        v.tab[v.ntab].n = x.n
        v.ntab += 1
        out.s = x.s
        out.n = x.n
        return OK
    if as_index(&x, &idx) and idx < v.ntab:
        out[0] = v.tab[idx]
        return OK
    return PY_PATH


cdef inline bint str_eq(StrRef* a, StrRef* b) noexcept nogil:
    return a.n == b.n and (a.n == 0 or memcmp(a.s, b.s, a.n) == 0)


cdef int kv_put(KV** pool, size_t* npool, size_t* cap, size_t off, size_t* n, StrRef* key, Val* val,
                bint only_if_absent) noexcept nogil:
    """dict[key] = val (or dict.setdefault) on the region pool[off:off + n], which ends the pool."""
    cdef size_t i
    for i in range(n[0]):
        if str_eq(&pool[0][off + i].key, key):
            if not only_if_absent:
                pool[0][off + i].val = val[0]
            return OK
    if n[0] >= V1_MAX_ATTRS:
        return PY_PATH
    if ensure(<void**>pool, cap, npool[0] + 1, sizeof(KV)) != OK:
        return NOMEM
    pool[0][npool[0]].key = key[0]
    pool[0][npool[0]].val = val[0]
    npool[0] += 1
    n[0] += 1
    return OK


cdef int parse_attrs(Ctx* c, V1* v, size_t* meta_off, size_t* meta_n, size_t* metrics_off,
                     size_t* metrics_n) noexcept nogil:
    cdef Val lst
    cdef Val ty
    cdef Val x
    cdef StrRef key
    cdef StrRef sval
    cdef uint64_t t
    cdef uint32_t j
    cdef int rc = read_val(c, &lst)
    if rc != OK:
        return rc
    if lst.kind != K_ARR or lst.n % 3 != 0:
        return PY_PATH
    meta_off[0] = v.nmeta
    meta_n[0] = 0
    metrics_off[0] = v.nmetrics
    metrics_n[0] = 0
    for j in range(lst.n // 3):
        rc = str_ref(c, v, &key)
        if rc != OK:
            return rc
        rc = read_val(c, &ty)
        if rc != OK:
            return rc
        if not as_index(&ty, &t):
            return PY_PATH
        if t == 1:  # STRING -> meta
            rc = str_ref(c, v, &sval)
            if rc != OK:
                return rc
            x.kind = K_STR
            x.s = sval.s
            x.n = sval.n
            rc = kv_put(&v.meta, &v.nmeta, &v.meta_cap, meta_off[0], meta_n, &key, &x, False)
        elif t == 2 or t == 3 or t == 4:  # BOOL / DOUBLE / INT -> metrics
            rc = read_val(c, &x)
            if rc != OK:
                return rc
            if t == 2:
                if x.kind != K_BOOL:
                    return PY_PATH
                x.kind = K_UINT  # 1 if value else 0
            elif not is_num(&x):
                return PY_PATH
            rc = kv_put(&v.metrics, &v.nmetrics, &v.metrics_cap, metrics_off[0], metrics_n, &key, &x, False)
        else:
            return PY_PATH  # BYTES / ARRAY / KEY_VALUE_LIST (meta_struct, flattening) or unknown
        if rc != OK:
            return rc
    return OK


cdef int parse_span(Ctx* c, V1* v) noexcept nogil:
    cdef Val m
    cdef Val k
    cdef Val x
    cdef uint64_t key
    cdef uint32_t seen = 0
    cdef uint32_t j
    cdef int rc
    cdef SpanIR* sp
    cdef size_t idx
    rc = read_val(c, &m)
    if rc != OK:
        return rc
    if m.kind != K_MAP:
        return PY_PATH
    if ensure(<void**>&v.spans, &v.spans_cap, v.nspans + 1, sizeof(SpanIR)) != OK:
        return NOMEM
    idx = v.nspans
    v.nspans += 1
    sp = &v.spans[idx]
    memset(sp, 0, sizeof(SpanIR))
    sp.kind = 0
    for j in range(m.n):
        rc = read_val(c, &k)
        if rc != OK:
            return rc
        if not as_index(&k, &key):
            if k.kind == K_INT or k.kind == K_NIL or k.kind == K_BIN or (k.kind == K_STR and utf8_ok(k.s, k.n)):
                key = 0  # never equal to a V1SpanKeys member: ignored
            else:
                return PY_PATH  # bool / float alias members; invalid str or unhashable keys raise
        if 1 <= key <= 16:
            if seen & (1u << key):
                return PY_PATH  # duplicate keys collapse before conversion
            seen |= 1u << key
            if key <= 10:
                sp.order[sp.norder] = <uint8_t>key
                sp.norder += 1
        sp = &v.spans[idx]
        if key == 1:
            rc = str_ref(c, v, &sp.service)
        elif key == 2:
            rc = str_ref(c, v, &sp.name)
            sp.has_name = True
        elif key == 3:
            rc = str_ref(c, v, &sp.resource)
        elif key == 10:
            rc = str_ref(c, v, &sp.type_)
        elif key == 13:
            rc = str_ref(c, v, &sp.env)
        elif key == 14:
            rc = str_ref(c, v, &sp.version)
        elif key == 15:
            rc = str_ref(c, v, &sp.component)
        elif key == 9:
            sp.has_attrs = True
            rc = parse_attrs(c, v, &sp.meta_off, &sp.meta_n, &sp.metrics_off, &sp.metrics_n)
        elif key == 11 or key == 12:
            return PY_PATH  # span links / events
        else:
            rc = read_val(c, &x)
            if rc != OK:
                return rc
            if key == 4:
                # pprint_trace needs a hashable, comparable span_id
                if not (x.kind == K_INT or x.kind == K_UINT):
                    return PY_PATH
                sp.span_id = x
                sp.has_span_id = True
            elif key == 5:
                if not (x.kind == K_INT or x.kind == K_UINT or x.kind == K_NIL):
                    return PY_PATH
                sp.parent_id = x
            elif key == 6:
                if not is_num(&x):
                    return PY_PATH  # pprint_trace sorts siblings by start
                sp.start = x
            elif key == 7:
                if not is_num(&x):
                    return PY_PATH
                sp.duration = x
            elif key == 8:
                if x.kind != K_BOOL:
                    return PY_PATH
                sp.error = x.u != 0
            elif key == 16:
                if x.kind != K_UINT or x.u > 5:
                    return PY_PATH
                sp.kind = <int>x.u
            else:
                rc = skip_value(c, &x, 1)
        if rc != OK:
            return rc
    sp = &v.spans[idx]
    # pprint_trace formats "[{name}]" and indexes span_id even though v1 spans are not verified.
    if not (sp.has_name and sp.has_span_id):
        return PY_PATH
    return OK


cdef int parse_chunk(Ctx* c, V1* v) noexcept nogil:
    cdef Val m
    cdef Val k
    cdef Val x
    cdef Val arr
    cdef uint64_t key
    cdef uint32_t seen = 0
    cdef uint32_t j
    cdef uint32_t s
    cdef int rc
    cdef size_t idx
    cdef ChunkIR* ch
    cdef Id sid
    rc = read_val(c, &m)
    if rc != OK:
        return rc
    if m.kind != K_MAP:
        return PY_PATH
    if ensure(<void**>&v.chunks, &v.chunks_cap, v.nchunks + 1, sizeof(ChunkIR)) != OK:
        return NOMEM
    idx = v.nchunks
    v.nchunks += 1
    ch = &v.chunks[idx]
    memset(ch, 0, sizeof(ChunkIR))
    ch.span_off = v.nspans
    for j in range(m.n):
        rc = read_val(c, &k)
        if rc != OK:
            return rc
        if not as_index(&k, &key) or key < 1 or key > 7 or key == 5:
            return PY_PATH  # unknown keys and droppedTrace raise
        if seen & (1u << key):
            return PY_PATH
        seen |= 1u << key
        ch = &v.chunks[idx]
        if key == 2:
            rc = str_ref(c, v, &ch.origin)
        elif key == 3:
            rc = parse_attrs(c, v, &ch.meta_off, &ch.meta_n, &ch.metrics_off, &ch.metrics_n)
        elif key == 4:
            rc = read_val(c, &arr)
            if rc != OK:
                return rc
            if arr.kind != K_ARR:
                return PY_PATH
            ch.span_off = v.nspans
            for s in range(arr.n):
                rc = parse_span(c, v)
                if rc != OK:
                    return rc
            ch = &v.chunks[idx]
            ch.span_n = arr.n
        else:
            rc = read_val(c, &x)
            if rc != OK:
                return rc
            if key == 1:
                if not (x.kind == K_INT or x.kind == K_UINT):
                    return PY_PATH
                ch.has_priority = True
                ch.priority = x
            elif key == 6:
                if x.kind != K_BIN or x.n != 16:
                    return PY_PATH
                ch.tid_hi = be64(x.s)
                ch.tid_lo = be64(x.s + 8)
            elif key == 7:
                if not (x.kind == K_INT or x.kind == K_UINT):
                    return PY_PATH
                ch.has_sm = True
                ch.sm = x
        if rc != OK:
            return rc
    ch = &v.chunks[idx]
    # Same pprint_trace termination guarantee as v0.4: unique, non-zero span_ids per chunk.
    for s in range(ch.span_n):
        as_id(&v.spans[ch.span_off + s].span_id, &sid)
        if push_id(c, &sid) != OK:
            return NOMEM
    return check_chunk_ids(c)


cdef int parse_payload(Ctx* c, V1* v) noexcept nogil:
    cdef Val m
    cdef Val k
    cdef Val x
    cdef Val arr
    cdef uint64_t key
    cdef uint32_t seen = 0
    cdef uint32_t j
    cdef uint32_t s
    cdef int rc
    rc = read_val(c, &m)
    if rc != OK:
        return rc
    if m.kind != K_MAP:
        return PY_PATH
    for j in range(m.n):
        rc = read_val(c, &k)
        if rc != OK:
            return rc
        if not as_index(&k, &key) or key < 2 or key > 11:
            return PY_PATH  # 1 (non-streamed strings) and unknown keys raise
        if seen & (1u << key):
            return PY_PATH
        seen |= 1u << key
        if key == 10:
            rc = parse_attrs(c, v, &v.pmeta_off, &v.pmeta_n, &v.pmetrics_off, &v.pmetrics_n)
        elif key == 11:
            rc = read_val(c, &arr)
            if rc != OK:
                return rc
            if arr.kind != K_ARR:
                return PY_PATH
            for s in range(arr.n):
                rc = parse_chunk(c, v)
                if rc != OK:
                    return rc
        else:
            rc = read_val(c, &x)
            if rc != OK:
                return rc
            if x.kind == K_STR:
                if not utf8_ok(x.s, x.n):
                    return PY_PATH
                if ensure(<void**>&v.tab, &v.tab_cap, v.ntab + 1, sizeof(StrRef)) != OK:
                    return NOMEM
                v.tab[v.ntab].s = x.s
                v.tab[v.ntab].n = x.n
                v.ntab += 1
            else:
                rc = skip_value(c, &x, 1)
        if rc != OK:
            return rc
    if c.p != c.end:
        return PY_PATH  # ExtraData: logged, still 200
    return OK


cdef int put_key(Ctx* c, const char* name, uint32_t n, bint* first) noexcept nogil:
    if not first[0] and put(c, b", ", 2) != OK:
        return NOMEM
    first[0] = False
    if putc(c, b'"') != OK or put(c, name, n) != OK or put(c, b"\": ", 3) != OK:
        return NOMEM
    return OK


cdef int put_num(Ctx* c, Val* x) noexcept nogil:
    if x.kind == K_UINT:
        return put_u64(c, x.u)
    if x.kind == K_INT:
        return put_i64(c, x.i)
    if x.kind == K_FLOAT:
        return put_double(c, x.f)
    return put(c, b"null", 4)


cdef int put_kv_map(Ctx* c, KV* kv, size_t n, bint strings) noexcept nogil:
    cdef size_t i
    cdef int rc
    if putc(c, b'{') != OK:
        return NOMEM
    for i in range(n):
        if i and put(c, b", ", 2) != OK:
            return NOMEM
        rc = put_str(c, kv[i].key.s, kv[i].key.n)
        if rc != OK:
            return rc
        if put(c, b": ", 2) != OK:
            return NOMEM
        rc = put_str(c, kv[i].val.s, kv[i].val.n) if strings else put_num(c, &kv[i].val)
        if rc != OK:
            return rc
    return putc(c, b'}')


cdef int scratch_put(V1* v, size_t* n, const char* key, uint32_t keylen, Val* val, bint only_if_absent) noexcept nogil:
    cdef StrRef k
    cdef size_t i
    k.s = <const uint8_t*>key
    k.n = keylen
    for i in range(n[0]):
        if str_eq(&v.scratch[i].key, &k):
            if not only_if_absent:
                v.scratch[i].val = val[0]
            return OK
    if ensure(<void**>&v.scratch, &v.scratch_cap, n[0] + 1, sizeof(KV)) != OK:
        return NOMEM
    v.scratch[n[0]].key = k
    v.scratch[n[0]].val = val[0]
    n[0] += 1
    return OK


cdef inline void str_val(Val* out, const uint8_t* s, uint32_t n) noexcept nogil:
    out.kind = K_STR
    out.s = s
    out.n = n


cdef int emit_meta(Ctx* c, V1* v, ChunkIR* ch, SpanIR* sp, bint first_span) noexcept nogil:
    """Final span["meta"]: span attributes, then the fields _convert_v1_span/_chunk/_payload add."""
    cdef size_t n = 0
    cdef size_t i
    cdef Val x
    cdef char tid[24]
    cdef char dm[32]
    cdef int len_
    cdef const char* kinds[6]
    kinds[0] = b""
    kinds[1] = b"internal"
    kinds[2] = b"server"
    kinds[3] = b"client"
    kinds[4] = b"producer"
    kinds[5] = b"consumer"
    for i in range(sp.meta_n):
        if scratch_put(v, &n, <const char*>v.meta[sp.meta_off + i].key.s, v.meta[sp.meta_off + i].key.n,
                       &v.meta[sp.meta_off + i].val, False) != OK:
            return NOMEM
    if sp.env.n:
        str_val(&x, sp.env.s, sp.env.n)
        if scratch_put(v, &n, b"env", 3, &x, False) != OK:
            return NOMEM
    if sp.version.n:
        str_val(&x, sp.version.s, sp.version.n)
        if scratch_put(v, &n, b"version", 7, &x, False) != OK:
            return NOMEM
    if sp.component.n:
        str_val(&x, sp.component.s, sp.component.n)
        if scratch_put(v, &n, b"component", 9, &x, False) != OK:
            return NOMEM
    if sp.kind > 0:
        str_val(&x, <const uint8_t*>kinds[sp.kind], <uint32_t>strlen(kinds[sp.kind]))
        if scratch_put(v, &n, b"span.kind", 9, &x, False) != OK:
            return NOMEM
    if ch.tid_hi != 0:
        len_ = snprintf(tid, sizeof(tid), b"%016llx", <unsigned long long>ch.tid_hi)
        str_val(&x, <const uint8_t*>tid, <uint32_t>len_)
        if scratch_put(v, &n, b"_dd.p.tid", 9, &x, False) != OK:
            return NOMEM
    if first_span and ch.has_sm and not (ch.sm.kind == K_UINT and ch.sm.u == 0) and not (ch.sm.kind == K_INT and ch.sm.i == 0):
        if ch.sm.kind == K_UINT:
            len_ = snprintf(dm, sizeof(dm), b"-%llu", <unsigned long long>ch.sm.u)
        else:
            len_ = snprintf(dm, sizeof(dm), b"-%lld", <long long>ch.sm.i)
        str_val(&x, <const uint8_t*>dm, <uint32_t>len_)
        if scratch_put(v, &n, b"_dd.p.dm", 8, &x, False) != OK:
            return NOMEM
    if ch.origin.n:
        str_val(&x, ch.origin.s, ch.origin.n)
        if scratch_put(v, &n, b"_dd.origin", 10, &x, False) != OK:
            return NOMEM
    for i in range(ch.meta_n):
        if scratch_put(v, &n, <const char*>v.meta[ch.meta_off + i].key.s, v.meta[ch.meta_off + i].key.n,
                       &v.meta[ch.meta_off + i].val, False) != OK:
            return NOMEM
    for i in range(v.pmeta_n):
        if scratch_put(v, &n, <const char*>v.meta[v.pmeta_off + i].key.s, v.meta[v.pmeta_off + i].key.n,
                       &v.meta[v.pmeta_off + i].val, True) != OK:
            return NOMEM
    return put_kv_map(c, v.scratch, n, True)


cdef int emit_metrics(Ctx* c, V1* v, ChunkIR* ch, SpanIR* sp) noexcept nogil:
    cdef size_t n = 0
    cdef size_t i
    for i in range(sp.metrics_n):
        if scratch_put(v, &n, <const char*>v.metrics[sp.metrics_off + i].key.s, v.metrics[sp.metrics_off + i].key.n,
                       &v.metrics[sp.metrics_off + i].val, False) != OK:
            return NOMEM
    if ch.has_priority:
        if scratch_put(v, &n, b"_sampling_priority_v1", 21, &ch.priority, False) != OK:
            return NOMEM
    for i in range(ch.metrics_n):
        if scratch_put(v, &n, <const char*>v.metrics[ch.metrics_off + i].key.s, v.metrics[ch.metrics_off + i].key.n,
                       &v.metrics[ch.metrics_off + i].val, False) != OK:
            return NOMEM
    for i in range(v.pmetrics_n):
        if scratch_put(v, &n, <const char*>v.metrics[v.pmetrics_off + i].key.s, v.metrics[v.pmetrics_off + i].key.n,
                       &v.metrics[v.pmetrics_off + i].val, True) != OK:
            return NOMEM
    return put_kv_map(c, v.scratch, n, False)


cdef int emit_v1_span(Ctx* c, V1* v, ChunkIR* ch, SpanIR* sp, bint first_span) noexcept nogil:
    cdef bint first = True
    cdef int i
    cdef int rc = OK
    cdef uint8_t f
    if putc(c, b'{') != OK:
        return NOMEM
    for i in range(sp.norder):
        f = sp.order[i]
        if f == 1:
            rc = put_key(c, b"service", 7, &first)
            if rc == OK:
                rc = put_str(c, sp.service.s, sp.service.n)
        elif f == 2:
            rc = put_key(c, b"name", 4, &first)
            if rc == OK:
                rc = put_str(c, sp.name.s, sp.name.n)
        elif f == 3:
            rc = put_key(c, b"resource", 8, &first)
            if rc == OK:
                rc = put_str(c, sp.resource.s, sp.resource.n)
        elif f == 4:
            rc = put_key(c, b"span_id", 7, &first)
            if rc == OK:
                rc = put_num(c, &sp.span_id)
        elif f == 5:
            rc = put_key(c, b"parent_id", 9, &first)
            if rc == OK:
                rc = put_num(c, &sp.parent_id)
        elif f == 6:
            rc = put_key(c, b"start", 5, &first)
            if rc == OK:
                rc = put_num(c, &sp.start)
        elif f == 7:
            rc = put_key(c, b"duration", 8, &first)
            if rc == OK:
                rc = put_num(c, &sp.duration)
        elif f == 8:
            rc = put_key(c, b"error", 5, &first)
            if rc == OK:
                rc = putc(c, b'1' if sp.error else b'0')
        elif f == 9:
            rc = put_key(c, b"meta", 4, &first)
            if rc == OK:
                rc = emit_meta(c, v, ch, sp, first_span)
            if rc == OK:
                rc = put_key(c, b"metrics", 7, &first)
            if rc == OK:
                rc = emit_metrics(c, v, ch, sp)
        elif f == 10:
            rc = put_key(c, b"type", 4, &first)
            if rc == OK:
                rc = put_str(c, sp.type_.s, sp.type_.n)
        if rc != OK:
            return rc
    if not sp.has_attrs:
        # "meta" is added at the end of _convert_v1_span, "metrics" by _convert_v1_chunk.
        rc = put_key(c, b"meta", 4, &first)
        if rc == OK:
            rc = emit_meta(c, v, ch, sp, first_span)
        if rc == OK:
            rc = put_key(c, b"metrics", 7, &first)
        if rc == OK:
            rc = emit_metrics(c, v, ch, sp)
        if rc != OK:
            return rc
    rc = put_key(c, b"trace_id", 8, &first)
    if rc == OK:
        rc = put_u64(c, ch.tid_lo)
    if rc != OK:
        return rc
    return putc(c, b'}')


cdef int transcode_v1_ctx(Ctx* c, V1* v) noexcept nogil:
    cdef int rc
    cdef size_t i
    cdef size_t s
    cdef size_t start
    cdef ChunkIR* ch
    cdef Id tid
    if ensure(<void**>&v.tab, &v.tab_cap, 1, sizeof(StrRef)) != OK:
        return NOMEM
    v.tab[0].s = <const uint8_t*>b""  # 0 is reserved for the empty string
    v.tab[0].n = 0
    v.ntab = 1
    rc = parse_payload(c, v)
    if rc != OK:
        return rc
    for i in range(v.nchunks):
        ch = &v.chunks[i]
        if ch.span_n == 0:
            continue
        start = c.len
        for s in range(ch.span_n):
            if s and put(c, b", ", 2) != OK:
                return NOMEM
            rc = emit_v1_span(c, v, ch, &v.spans[ch.span_off + s], s == 0)
            if rc != OK:
                return rc
        tid.u = ch.tid_lo
        tid.neg = 0
        rc = add_run(c, &tid, start, c.len)
        if rc != OK:
            return rc
    return OK


def transcode_v1(const uint8_t[::1] data not None):
    """Like transcode_v04, for /v1.0/traces payloads (trace.decode_v1)."""
    cdef Ctx c
    cdef V1 v
    cdef int rc
    if data.shape[0] == 0:
        return None
    ctx_init(&c, <size_t>data.shape[0] * 8 + 1024)
    if c.out == NULL:
        raise MemoryError()
    memset(&v, 0, sizeof(V1))
    c.p = &data[0]
    c.end = c.p + data.shape[0]
    try:
        with nogil:
            rc = transcode_v1_ctx(&c, &v)
        return _result(&c, rc)
    finally:
        ctx_free(&c)
        free(v.tab)
        free(v.meta)
        free(v.metrics)
        free(v.spans)
        free(v.chunks)
        free(v.scratch)


# ---- test hooks ---------------------------------------------------------------------------
def format_double(double v):
    """What json.dumps writes for float v (for parity fuzzing)."""
    cdef Ctx c
    ctx_init(&c, 64)
    try:
        if put_double(&c, v) != OK:
            return None
        return PyBytes_FromStringAndSize(<char*>c.out, c.len).decode()
    finally:
        ctx_free(&c)


def format_str(const uint8_t[::1] data not None):
    """What json.dumps writes for data.decode() (for parity fuzzing), or None if invalid."""
    cdef Ctx c
    ctx_init(&c, 64)
    try:
        if put_str(&c, &data[0] if data.shape[0] else NULL, data.shape[0]) != OK:
            return None
        return PyBytes_FromStringAndSize(<char*>c.out, c.len).decode()
    finally:
        ctx_free(&c)
