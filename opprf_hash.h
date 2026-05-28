#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <immintrin.h>
#include <string>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

namespace linerpsu::opprf_hash {

constexpr size_t kMaxHbBits = 128;
constexpr size_t kDefaultHbBits = 64;

inline uint64_t EnvU64(const char* name, uint64_t fallback) {
  const char* value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }
  return std::stoull(value);
}

inline size_t EffectiveHbBits() {
  const size_t hb_bits = EnvU64("LINERPSU_OPPRF_HB_BITS", kDefaultHbBits);
  YACL_ENFORCE(hb_bits > 0 && hb_bits <= kMaxHbBits,
               "LINERPSU_OPPRF_HB_BITS must be in [1, 128]");
  return hb_bits;
}

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
__attribute__((target("avx512f,avx512bw,vaes"))) inline uint8_t LsbBits512(
    __m512i state) {
  const uint64_t mask =
      _mm512_movepi8_mask(_mm512_slli_epi16(state, 7));
  return static_cast<uint8_t>(((mask >> 15U) & 1U) |
                              (((mask >> 31U) & 1U) << 1U) |
                              (((mask >> 47U) & 1U) << 2U) |
                              (((mask >> 63U) & 1U) << 3U));
}

__attribute__((target("avx512f,avx512bw,vaes"))) inline void EvalOneVaes512(
    uint128_t& out, const uint128_t* keys, const uint128_t& input,
    size_t count) {
  uint8_t result[16] = {0};
  const __m128i input_block =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(&input));
  const __m512i input_blocks = _mm512_broadcast_i32x4(input_block);

  size_t i = 0;
  for (; i + 4 <= count; i += 4) {
    const __m512i key_blocks =
        _mm512_loadu_si512(reinterpret_cast<const void*>(keys + i));
    __m512i state = _mm512_xor_si512(input_blocks, key_blocks);
    state = _mm512_aesenc_epi128(state, key_blocks);
    state = _mm512_aesenclast_epi128(state, key_blocks);
    const uint8_t bits = LsbBits512(state);
    result[i >> 3] |= static_cast<uint8_t>(bits << (i & 7U));
  }

  for (; i < count; ++i) {
    const __m128i key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&keys[i]));
    __m128i state = _mm_xor_si128(input_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    const int bit = _mm_extract_epi8(state, 15) & 1;
    result[i >> 3] |= static_cast<uint8_t>(bit << (i & 7U));
  }
  std::memcpy(&out, result, sizeof(out));
}

__attribute__((target("avx512f,avx512bw,vaes"))) inline void
EvalAAndDOneVaes512(uint128_t& out_a, uint128_t& out_d,
                    const uint128_t* a_keys, const uint128_t* b_keys,
                    const uint128_t& input, size_t count) {
  uint8_t result_a[16] = {0};
  uint8_t result_d[16] = {0};
  const __m128i input_block =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(&input));
  const __m512i input_blocks = _mm512_broadcast_i32x4(input_block);

  size_t i = 0;
  for (; i + 4 <= count; i += 4) {
    const __m512i a_key_blocks =
        _mm512_loadu_si512(reinterpret_cast<const void*>(a_keys + i));
    const __m512i b_key_blocks =
        _mm512_loadu_si512(reinterpret_cast<const void*>(b_keys + i));
    __m512i state_a = _mm512_xor_si512(input_blocks, a_key_blocks);
    __m512i state_b = _mm512_xor_si512(input_blocks, b_key_blocks);
    state_a = _mm512_aesenc_epi128(state_a, a_key_blocks);
    state_b = _mm512_aesenc_epi128(state_b, b_key_blocks);
    state_a = _mm512_aesenclast_epi128(state_a, a_key_blocks);
    state_b = _mm512_aesenclast_epi128(state_b, b_key_blocks);
    const uint8_t bits_a = LsbBits512(state_a);
    const uint8_t bits_b = LsbBits512(state_b);
    result_a[i >> 3] |= static_cast<uint8_t>(bits_a << (i & 7U));
    result_d[i >> 3] |= static_cast<uint8_t>((bits_a ^ bits_b) << (i & 7U));
  }

  for (; i < count; ++i) {
    const __m128i a_key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&a_keys[i]));
    const __m128i b_key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&b_keys[i]));
    __m128i state_a = _mm_xor_si128(input_block, a_key_block);
    __m128i state_b = _mm_xor_si128(input_block, b_key_block);
    state_a = _mm_aesenc_si128(state_a, a_key_block);
    state_b = _mm_aesenc_si128(state_b, b_key_block);
    state_a = _mm_aesenclast_si128(state_a, a_key_block);
    state_b = _mm_aesenclast_si128(state_b, b_key_block);
    const int bit_a = _mm_extract_epi8(state_a, 15) & 1;
    const int bit_b = _mm_extract_epi8(state_b, 15) & 1;
    result_a[i >> 3] |= static_cast<uint8_t>(bit_a << (i & 7U));
    result_d[i >> 3] |= static_cast<uint8_t>((bit_a ^ bit_b) << (i & 7U));
  }
  std::memcpy(&out_a, result_a, sizeof(out_a));
  std::memcpy(&out_d, result_d, sizeof(out_d));
}

__attribute__((target("avx2,vaes"))) inline uint8_t LsbBits256(
    __m256i state) {
  const uint32_t mask =
      static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_slli_epi16(state, 7)));
  return static_cast<uint8_t>(((mask >> 15U) & 1U) |
                              (((mask >> 31U) & 1U) << 1U));
}

__attribute__((target("avx2,vaes"))) inline void EvalOneVaes256(
    uint128_t& out, const uint128_t* keys, const uint128_t& input,
    size_t count) {
  uint8_t result[16] = {0};
  const __m128i input_block =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(&input));
  const __m256i input_blocks = _mm256_broadcastsi128_si256(input_block);

  size_t i = 0;
  for (; i + 2 <= count; i += 2) {
    const __m256i key_blocks =
        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(keys + i));
    __m256i state = _mm256_xor_si256(input_blocks, key_blocks);
    state = _mm256_aesenc_epi128(state, key_blocks);
    state = _mm256_aesenclast_epi128(state, key_blocks);
    const uint8_t bits = LsbBits256(state);
    result[i >> 3] |= static_cast<uint8_t>(bits << (i & 7U));
  }

  for (; i < count; ++i) {
    const __m128i key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&keys[i]));
    __m128i state = _mm_xor_si128(input_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    const int bit = _mm_extract_epi8(state, 15) & 1;
    result[i >> 3] |= static_cast<uint8_t>(bit << (i & 7U));
  }
  std::memcpy(&out, result, sizeof(out));
}

__attribute__((target("avx2,vaes"))) inline void EvalAAndDOneVaes256(
    uint128_t& out_a, uint128_t& out_d, const uint128_t* a_keys,
    const uint128_t* b_keys, const uint128_t& input, size_t count) {
  uint8_t result_a[16] = {0};
  uint8_t result_d[16] = {0};
  const __m128i input_block =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(&input));
  const __m256i input_blocks = _mm256_broadcastsi128_si256(input_block);

  size_t i = 0;
  for (; i + 2 <= count; i += 2) {
    const __m256i a_key_blocks =
        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a_keys + i));
    const __m256i b_key_blocks =
        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b_keys + i));
    __m256i state_a = _mm256_xor_si256(input_blocks, a_key_blocks);
    __m256i state_b = _mm256_xor_si256(input_blocks, b_key_blocks);
    state_a = _mm256_aesenc_epi128(state_a, a_key_blocks);
    state_b = _mm256_aesenc_epi128(state_b, b_key_blocks);
    state_a = _mm256_aesenclast_epi128(state_a, a_key_blocks);
    state_b = _mm256_aesenclast_epi128(state_b, b_key_blocks);
    const uint8_t bits_a = LsbBits256(state_a);
    const uint8_t bits_b = LsbBits256(state_b);
    result_a[i >> 3] |= static_cast<uint8_t>(bits_a << (i & 7U));
    result_d[i >> 3] |= static_cast<uint8_t>((bits_a ^ bits_b) << (i & 7U));
  }

  for (; i < count; ++i) {
    const __m128i a_key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&a_keys[i]));
    const __m128i b_key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&b_keys[i]));
    __m128i state_a = _mm_xor_si128(input_block, a_key_block);
    __m128i state_b = _mm_xor_si128(input_block, b_key_block);
    state_a = _mm_aesenc_si128(state_a, a_key_block);
    state_b = _mm_aesenc_si128(state_b, b_key_block);
    state_a = _mm_aesenclast_si128(state_a, a_key_block);
    state_b = _mm_aesenclast_si128(state_b, b_key_block);
    const int bit_a = _mm_extract_epi8(state_a, 15) & 1;
    const int bit_b = _mm_extract_epi8(state_b, 15) & 1;
    result_a[i >> 3] |= static_cast<uint8_t>(bit_a << (i & 7U));
    result_d[i >> 3] |= static_cast<uint8_t>((bit_a ^ bit_b) << (i & 7U));
  }
  std::memcpy(&out_a, result_a, sizeof(out_a));
  std::memcpy(&out_d, result_d, sizeof(out_d));
}
#endif

inline void EvalOne(uint128_t& out, const uint128_t* keys,
                    const uint128_t& input, size_t count) {
  uint8_t result[16] = {0};
  const __m128i input_block =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(&input));
  for (size_t i = 0; i < count; ++i) {
    const __m128i key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&keys[i]));
    __m128i state = _mm_xor_si128(input_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    const int bit = _mm_extract_epi8(state, 15) & 1;
    result[i >> 3] |= static_cast<uint8_t>(bit << (i & 7U));
  }
  std::memcpy(&out, result, sizeof(out));
}

inline void EvalAAndDOne(uint128_t& out_a, uint128_t& out_d,
                         const uint128_t* a_keys, const uint128_t* b_keys,
                         const uint128_t& input, size_t count) {
  uint8_t result_a[16] = {0};
  uint8_t result_d[16] = {0};
  const __m128i input_block =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(&input));
  for (size_t i = 0; i < count; ++i) {
    const __m128i a_key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&a_keys[i]));
    const __m128i b_key_block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(&b_keys[i]));
    __m128i state_a = _mm_xor_si128(input_block, a_key_block);
    __m128i state_b = _mm_xor_si128(input_block, b_key_block);
    state_a = _mm_aesenc_si128(state_a, a_key_block);
    state_b = _mm_aesenc_si128(state_b, b_key_block);
    state_a = _mm_aesenclast_si128(state_a, a_key_block);
    state_b = _mm_aesenclast_si128(state_b, b_key_block);
    const int bit_a = _mm_extract_epi8(state_a, 15) & 1;
    const int bit_b = _mm_extract_epi8(state_b, 15) & 1;
    result_a[i >> 3] |= static_cast<uint8_t>(bit_a << (i & 7U));
    result_d[i >> 3] |= static_cast<uint8_t>((bit_a ^ bit_b) << (i & 7U));
  }
  std::memcpy(&out_a, result_a, sizeof(out_a));
  std::memcpy(&out_d, result_d, sizeof(out_d));
}

inline void EvalMany(uint128_t* out, const uint128_t* keys,
                     const uint128_t* inputs, size_t n, size_t count) {
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
  static const bool has_vaes512 =
      EnvU64("LINERPSU_OPPRF_AVX512", 0) != 0 &&
      __builtin_cpu_supports("avx512f") &&
      __builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("vaes");
  if (has_vaes512) {
    for (size_t i = 0; i < n; ++i) {
      EvalOneVaes512(out[i], keys, inputs[i], count);
    }
    return;
  }
  static const bool has_vaes256 =
      __builtin_cpu_supports("avx2") && __builtin_cpu_supports("vaes");
  if (has_vaes256) {
    for (size_t i = 0; i < n; ++i) {
      EvalOneVaes256(out[i], keys, inputs[i], count);
    }
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    EvalOne(out[i], keys, inputs[i], count);
  }
}

inline void EvalAAndDMany(uint128_t* out_a, uint128_t* out_d,
                          const uint128_t* a_keys, const uint128_t* b_keys,
                          const uint128_t* inputs, size_t n, size_t count) {
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
  static const bool has_vaes512 =
      EnvU64("LINERPSU_OPPRF_AVX512", 0) != 0 &&
      __builtin_cpu_supports("avx512f") &&
      __builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("vaes");
  if (has_vaes512) {
    for (size_t i = 0; i < n; ++i) {
      EvalAAndDOneVaes512(out_a[i], out_d[i], a_keys, b_keys, inputs[i],
                          count);
    }
    return;
  }
  static const bool has_vaes256 =
      __builtin_cpu_supports("avx2") && __builtin_cpu_supports("vaes");
  if (has_vaes256) {
    for (size_t i = 0; i < n; ++i) {
      EvalAAndDOneVaes256(out_a[i], out_d[i], a_keys, b_keys, inputs[i],
                          count);
    }
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    EvalAAndDOne(out_a[i], out_d[i], a_keys, b_keys, inputs[i], count);
  }
}

}  // namespace linerpsu::opprf_hash
