#pragma once
#include <wmmintrin.h>

#include <cstddef>
#include <cstdint>
#include <unordered_set>
#include <vector>

#include "examples/linerpsu/cuckoohash.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

struct U128Hasher {
  size_t operator()(const uint128_t& val) const {
    return static_cast<size_t>(val >> 64) ^ static_cast<size_t>(val);
  }
};

inline void aes128_encrypt_batch(uint128_t& a_out, const uint128_t keys[128],
                                 const uint128_t& y) {
  __m128i y_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&y));

  uint8_t result_bytes[16] = {0};

  for (size_t i = 0; i < 128; ++i) {
    const __m128i* key_ptr = reinterpret_cast<const __m128i*>(&keys[i]);
    __m128i key_block = _mm_loadu_si128(key_ptr);

    __m128i state = _mm_xor_si128(y_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    alignas(16) uint8_t cipher[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipher), state);
    int bit = cipher[15] & 1;
    result_bytes[i >> 3] |= (bit << (i % 8));
  }
  std::memcpy(&a_out, result_bytes, 16);
}

inline void aes128_encrypt_batch(uint128_t& a_out, const uint128_t* keys,
                                 const uint128_t& y, size_t kappa) {
  __m128i y_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&y));

  uint8_t result_bytes[16] = {0};

  for (size_t i = 0; i < kappa; ++i) {
    const __m128i* key_ptr = reinterpret_cast<const __m128i*>(&keys[i]);
    __m128i key_block = _mm_loadu_si128(key_ptr);

    __m128i state = _mm_xor_si128(y_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);

    alignas(16) uint8_t cipher[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipher), state);

    int bit = cipher[15] & 1;
    result_bytes[i >> 3] |= (bit << (i % 8));
  }

  std::memcpy(&a_out, result_bytes, 16);
}

inline std::vector<bool> GetIntersectionMask(const std::vector<uint128_t>& x,
                                             const std::vector<uint128_t>& y,
                                             std::vector<bool>& mask) {
  std::unordered_set<uint128_t, U128Hasher> y_set(y.begin(), y.end());
  yacl::parallel_for(0, x.size(), [&](size_t start, size_t end) {
    for (size_t i = start; i < end; ++i) {
      if (y_set.contains(x[i])) {
        mask[i] = true;
      }
    }
  });

  return mask;
}

inline void FakePEQT(const std::vector<uint128_t>& x,
                     const std::vector<uint128_t>& y, std::vector<bool>& out_a,
                     std::vector<bool>& out_b) {
  size_t n = x.size();
  YACL_ENFORCE(y.size() == n, "x and y must be same length");
  out_a.resize(n);
  out_b.resize(n);
  size_t m = 0;
  auto rand_bits = yacl::crypto::FastRandBits(n);
  for (size_t i = 0; i < n; ++i) {
    bool eq_bit = x[i] == y[i];
    if (eq_bit) {
      m++;
    }
    out_a[i] = rand_bits[i];
    out_b[i] = eq_bit ^ out_a[i];
  }
  std::cout << "FakePEQT: " << m << std::endl;
}

inline void FakePiPEQT(const std::vector<uint128_t>& x1,
                       const std::vector<uint128_t>& x2,
                       const std::vector<uint128_t>& y, std::vector<size_t>& pi,
                       std::vector<bool>& out_a, std::vector<bool>& out_b) {
  size_t n = pi.size();
  out_a.resize(n);
  out_b.resize(n);
  auto rand_bits = yacl::crypto::FastRandBits(n);
  for (size_t i = 0; i < n; ++i) {
    bool eq_bit = (x1[i] ^ x2[i]) == y[pi[i]];
    out_a[i] = rand_bits[i];
    out_b[i] = eq_bit ^ out_a[i];
  }
}

inline std::vector<size_t> GenShuffledRangeWithYacl(size_t n) {
  std::vector<size_t> perm(n);
  for (size_t i = 0; i < n; ++i) {
    perm[i] = i;
  }
  auto rng = []() {
    return static_cast<uint32_t>(yacl::crypto::SecureRandU128());
  };
  std::shuffle(perm.begin(), perm.end(), std::mt19937(rng()));
  return perm;
}

inline void Fakessoprf(std::vector<size_t> pi, uint128_t k,
                       std::vector<uint128_t>& out_a,
                       std::vector<uint128_t>& out_b) {
  size_t n = pi.size();
  out_a.resize(n);
  out_b.resize(n);
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      size_t idx1 = pi[idx];
      uint128_t fx = yacl::crypto::Blake3_128(yacl::SerializeUint128(k ^ idx1));
      out_a[idx] = yacl::crypto::FastRandU128();
      out_b[idx] = fx ^ out_a[idx];
    }
  });
}

inline std::vector<uint128_t> ShuffleWithYacl(CuckooHash t_x,
                                              const std::vector<size_t>& perm) {
  size_t n = t_x.cuckoolen_;
  YACL_ENFORCE(perm.size() == n, "Permutation size must match input size");
  std::vector<uint128_t> output(n);
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      if (t_x.hash_index_[perm[i]] == 0) {
        output[i] = 0;
      } else {
        output[i] = t_x.bins_[perm[i]];
      }
    }
  });
  return output;
}
