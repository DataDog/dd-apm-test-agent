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
from libc.string cimport memcpy, memcmp
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


def transcode_v04(const uint8_t[::1] data not None):
    """Return (json_bytes, [(trace_id, start, end), ...]) or None for the Python path.

    body[start:end] is ", ".join(json.dumps(span) for span in run): a run of consecutive spans
    with the same trace_id, exactly as json.dumps renders them inside the session response.
    """
    cdef Ctx c
    cdef int rc
    cdef size_t i
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
    finally:
        ctx_free(&c)


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
