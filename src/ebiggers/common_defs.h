#ifndef _COMMON_DEFS_H
#define _COMMON_DEFS_H

// #include <ntfs-3g/endians.h>
// #include <ntfs-3g/types.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;

/* ========================================================================== */
/*                              Type definitions                              */
/* ========================================================================== */

/*
 * Type of a machine word.  'unsigned long' would be logical, but that is only
 * 32 bits on x86_64 Windows.  The same applies to 'uint_fast32_t'.  So the best
 * we can do without a bunch of #ifdefs appears to be 'size_t'.
 */
typedef size_t machine_word_t;

#define WORDBYTES	sizeof(machine_word_t)
#define WORDBITS	(8 * WORDBYTES)

/* ========================================================================== */
/*                         Compiler-specific definitions                      */
/* ========================================================================== */

#ifdef __GNUC__  /* GCC, or GCC-compatible compiler such as clang */
#  define forceinline		inline __attribute__((always_inline))
#  define likely(expr)		__builtin_expect(!!(expr), 1)
#  define unlikely(expr)	__builtin_expect(!!(expr), 0)
#  define _aligned_attribute(n)	__attribute__((aligned(n)))
#  define bsr32(n)		(31 - __builtin_clz(n))
#  define bsr64(n)		(63 - __builtin_clzll(n))
#  define bsf32(n)		__builtin_ctz(n)
#  define bsf64(n)		__builtin_ctzll(n)
#  ifndef min
#    define min(a, b)  ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); \
			(_a < _b) ? _a : _b; })
#  endif
#  ifndef max
#    define max(a, b)  ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); \
			(_a > _b) ? _a : _b; })
#  endif

#  define DEFINE_UNALIGNED_TYPE(type)				\
struct type##_unaligned {					\
	type v;							\
} __attribute__((packed));					\
								\
static inline type						\
load_##type##_unaligned(const void *p)				\
{								\
	return ((const struct type##_unaligned *)p)->v;		\
}								\
								\
static inline void						\
store_##type##_unaligned(type val, void *p)			\
{								\
	((struct type##_unaligned *)p)->v = val;		\
}

#endif /* __GNUC__ */

/* Declare that the annotated function should always be inlined.  This might be
 * desirable in highly tuned code, e.g. compression codecs */
#ifndef forceinline
#  define forceinline		inline
#endif

/* Hint that the expression is usually true */
#ifndef likely
#  define likely(expr)		(expr)
#endif

/* Hint that the expression is usually false */
#ifndef unlikely
#  define unlikely(expr)	(expr)
#endif

/* Declare that the annotated variable, or variables of the annotated type, are
 * to be aligned on n-byte boundaries */
#ifndef _aligned_attribute
#  define _aligned_attribute(n)
#endif

/* min() and max() macros */
#ifndef min
#  define min(a, b)	((a) < (b) ? (a) : (b))
#endif
#ifndef max
#  define max(a, b)	((a) > (b) ? (a) : (b))
#endif

/* STATIC_ASSERT() - verify the truth of an expression at compilation time */
#define STATIC_ASSERT(expr)	((void)sizeof(char[1 - 2 * !(expr)]))

/* STATIC_ASSERT_ZERO() - verify the truth of an expression at compilation time
 * and also produce a result of value '0' to be used in constant expressions */
#define STATIC_ASSERT_ZERO(expr) ((int)sizeof(char[-!(expr)]))

/* UNALIGNED_ACCESS_IS_FAST should be defined to 1 if unaligned memory accesses
 * can be performed efficiently on the target platform.  */
#if defined(__x86_64__) || defined(__i386__) || defined(__ARM_FEATURE_UNALIGNED)
#  define UNALIGNED_ACCESS_IS_FAST 1
#else
#  define UNALIGNED_ACCESS_IS_FAST 0
#endif

/*
 * DEFINE_UNALIGNED_TYPE(type) - a macro that, given an integer type 'type',
 * defines load_type_unaligned(addr) and store_type_unaligned(v, addr) functions
 * which load and store variables of type 'type' from/to unaligned memory
 * addresses.
 */
#ifndef DEFINE_UNALIGNED_TYPE

#include <string.h>
/*
 * Although memcpy() may seem inefficient, it *usually* gets optimized
 * appropriately by modern compilers.  It's portable and may be the best we can
 * do for a fallback...
 */
#define DEFINE_UNALIGNED_TYPE(type)				\
								\
static forceinline type						\
load_##type##_unaligned(const void *p)				\
{								\
	type v;							\
	memcpy(&v, p, sizeof(v));				\
	return v;						\
}								\
								\
static forceinline void						\
store_##type##_unaligned(type v, void *p)			\
{								\
	memcpy(p, &v, sizeof(v));				\
}

#endif /* !DEFINE_UNALIGNED_TYPE */


/* ========================================================================== */
/*                          Unaligned memory accesses                         */
/* ========================================================================== */

#define load_word_unaligned	load_machine_word_t_unaligned
#define store_word_unaligned	store_machine_word_t_unaligned

/* ========================================================================== */
/*                             Bit scan functions                             */
/* ========================================================================== */

/*
 * Bit Scan Reverse (BSR) - find the 0-based index (relative to the least
 * significant end) of the *most* significant 1 bit in the input value.  The
 * input value must be nonzero!
 */

#ifndef bsr32
static forceinline unsigned
bsr32(u32 v)
{
	unsigned bit = 0;
	while ((v >>= 1) != 0)
		bit++;
	return bit;
}
#endif

#ifndef bsr64
static forceinline unsigned
bsr64(u64 v)
{
	unsigned bit = 0;
	while ((v >>= 1) != 0)
		bit++;
	return bit;
}
#endif

static forceinline unsigned
bsrw(machine_word_t v)
{
	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
	if (WORDBITS == 32)
		return bsr32(v);
	else
		return bsr64(v);
}

/*
 * Bit Scan Forward (BSF) - find the 0-based index (relative to the least
 * significant end) of the *least* significant 1 bit in the input value.  The
 * input value must be nonzero!
 */

#ifndef bsf32
static forceinline unsigned
bsf32(u32 v)
{
	unsigned bit;
	for (bit = 0; !(v & 1); bit++, v >>= 1)
		;
	return bit;
}
#endif

#ifndef bsf64
static forceinline unsigned
bsf64(u64 v)
{
	unsigned bit;
	for (bit = 0; !(v & 1); bit++, v >>= 1)
		;
	return bit;
}
#endif

static forceinline unsigned
bsfw(machine_word_t v)
{
	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
	if (WORDBITS == 32)
		return bsf32(v);
	else
		return bsf64(v);
}

/* Return the log base 2 of 'n', rounded up to the nearest integer. */
static forceinline unsigned
ilog2_ceil(size_t n)
{
        if (n <= 1)
                return 0;
        return 1 + bsrw(n - 1);
}

/* ========================================================================== */
/*                          Aligned memory allocation                         */
/* ========================================================================== */

extern void *aligned_malloc(size_t size, size_t alignment);
extern void aligned_free(void *ptr);

#endif /* _COMMON_DEFS_H */
