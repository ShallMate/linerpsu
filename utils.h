#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <unordered_set>
#include <vector>

#include "examples/linerpsu/cuckoohash.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"
#include <cryptoTools/Common/block.h>
#include <iostream>
#include <chrono>
#include "securejoin_oc_compat.h"
#include <secure-join/Perm/PprfPermGen.h>
#include "secure-join/Perm/PermCorrelation.h"
#include "secure-join/Perm/AltModPerm.h"
#include "secure-join/Perm/Permutation.h"
#include "secure-join/CorGenerator/CorGenerator.h"
#include "macoro/sync_wait.h"
#include "macoro/start_on.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "macoro/inline_scheduler.h"
#include <secure-join/Prf/AltModPrf.h>


using namespace secJoin; 

struct U128Hasher {
  size_t operator()(const uint128_t& val) const {
    return static_cast<size_t>(val >> 64) ^ static_cast<size_t>(val);
  }
};

static inline void U128VecToU64Vec_Lo(const std::vector<uint128_t>& in,
                                      std::vector<uint64_t>* out) {
  const size_t n = in.size();
  out->resize(n);
  const uint128_t* p = in.data();
  uint64_t* q = out->data();

  for (size_t i = 0; i < n; ++i) {
    q[i] = static_cast<uint64_t>(p[i]);  // low 64
  }
}

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
__attribute__((target("avx2,vaes"))) inline void
aes128_encrypt_batch_vaes256(uint128_t& a_out, const uint128_t* keys,
                             const uint128_t& y, size_t kappa) {
  uint8_t result_bytes[16] = {0};
  const __m128i y_block = _mm_loadu_si128(
      reinterpret_cast<const __m128i*>(&y));
  const __m256i y_blocks = _mm256_broadcastsi128_si256(y_block);
  alignas(32) uint8_t cipher2[32];
  size_t i = 0;
  for (; i + 2 <= kappa; i += 2) {
    const __m256i key_blocks = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(keys + i));
    __m256i state = _mm256_xor_si256(y_blocks, key_blocks);
    state = _mm256_aesenc_epi128(state, key_blocks);
    state = _mm256_aesenclast_epi128(state, key_blocks);
    _mm256_store_si256(reinterpret_cast<__m256i*>(cipher2), state);

    const uint8_t bits = static_cast<uint8_t>((cipher2[15] & 1U) |
                                              ((cipher2[31] & 1U) << 1U));
    result_bytes[i >> 3] |= static_cast<uint8_t>(bits << (i & 7U));
  }

  for (; i < kappa; ++i) {
    const __m128i key_block = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(&keys[i]));
    __m128i state = _mm_xor_si128(y_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    const int bit = _mm_extract_epi8(state, 15) & 1;
    result_bytes[i >> 3] |= static_cast<uint8_t>(bit << (i & 7U));
  }
  std::memcpy(&a_out, result_bytes, 16);
}
#endif

inline void aes128_encrypt_batch(uint128_t& a_out, const uint128_t* keys,
                                 const uint128_t& y, size_t kappa) {
  uint8_t result_bytes[16] = {0};

#if defined(__VAES__) && defined(__AVX512F__)
  const __m128i y_block = _mm_loadu_si128(
      reinterpret_cast<const __m128i*>(&y));
  const __m512i y_blocks = _mm512_broadcast_i32x4(y_block);
  alignas(64) uint8_t cipher4[64];
  size_t i = 0;
  for (; i + 4 <= kappa; i += 4) {
    const __m512i key_blocks = _mm512_loadu_si512(
        reinterpret_cast<const void*>(keys + i));
    __m512i state = _mm512_xor_si512(y_blocks, key_blocks);
    state = _mm512_aesenc_epi128(state, key_blocks);
    state = _mm512_aesenclast_epi128(state, key_blocks);
    _mm512_store_si512(reinterpret_cast<__m512i*>(cipher4), state);

    const uint8_t bits =
        static_cast<uint8_t>((cipher4[15] & 1U) |
                             ((cipher4[31] & 1U) << 1U) |
                             ((cipher4[47] & 1U) << 2U) |
                             ((cipher4[63] & 1U) << 3U));
    result_bytes[i >> 3] |= static_cast<uint8_t>(bits << (i & 7U));
  }

  for (; i < kappa; ++i) {
    const __m128i key_block = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(&keys[i]));
    __m128i state = _mm_xor_si128(y_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    const int bit = _mm_extract_epi8(state, 15) & 1;
    result_bytes[i >> 3] |= static_cast<uint8_t>(bit << (i & 7U));
  }
#elif defined(__VAES__) && defined(__AVX2__)
  const __m128i y_block = _mm_loadu_si128(
      reinterpret_cast<const __m128i*>(&y));
  const __m256i y_blocks = _mm256_broadcastsi128_si256(y_block);
  alignas(32) uint8_t cipher2[32];
  size_t i = 0;
  for (; i + 2 <= kappa; i += 2) {
    const __m256i key_blocks = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(keys + i));
    __m256i state = _mm256_xor_si256(y_blocks, key_blocks);
    state = _mm256_aesenc_epi128(state, key_blocks);
    state = _mm256_aesenclast_epi128(state, key_blocks);
    _mm256_store_si256(reinterpret_cast<__m256i*>(cipher2), state);

    const uint8_t bits = static_cast<uint8_t>((cipher2[15] & 1U) |
                                              ((cipher2[31] & 1U) << 1U));
    result_bytes[i >> 3] |= static_cast<uint8_t>(bits << (i & 7U));
  }

  for (; i < kappa; ++i) {
    const __m128i key_block = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(&keys[i]));
    __m128i state = _mm_xor_si128(y_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    const int bit = _mm_extract_epi8(state, 15) & 1;
    result_bytes[i >> 3] |= static_cast<uint8_t>(bit << (i & 7U));
  }
#else
  __m128i y_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&y));

  for (size_t i = 0; i < kappa; ++i) {
    const __m128i* key_ptr = reinterpret_cast<const __m128i*>(&keys[i]);
    __m128i key_block = _mm_loadu_si128(key_ptr);

    __m128i state = _mm_xor_si128(y_block, key_block);
    state = _mm_aesenc_si128(state, key_block);
    state = _mm_aesenclast_si128(state, key_block);
    const int bit = _mm_extract_epi8(state, 15) & 1;
    result_bytes[i >> 3] |= static_cast<uint8_t>(bit << (i & 7U));
  }
#endif
  std::memcpy(&a_out, result_bytes, 16);
}

inline void aes128_encrypt_batch(uint128_t& a_out, const uint128_t keys[128],
                                 const uint128_t& y) {
  aes128_encrypt_batch(a_out, keys, y, 128);
}

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
__attribute__((target("avx2,vaes"))) inline void
aes128_encrypt_many_vaes256(uint128_t* out, const uint128_t* keys,
                            const uint128_t* inputs, size_t n, size_t kappa) {
  for (size_t i = 0; i < n; ++i) {
    aes128_encrypt_batch_vaes256(out[i], keys, inputs[i], kappa);
  }
}
#endif

inline void aes128_encrypt_many(uint128_t* out, const uint128_t* keys,
                                const uint128_t* inputs, size_t n,
                                size_t kappa = 128) {
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
  static const bool has_vaes256 =
      __builtin_cpu_supports("avx2") && __builtin_cpu_supports("vaes");
  if (has_vaes256) {
    aes128_encrypt_many_vaes256(out, keys, inputs, n, kappa);
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    aes128_encrypt_batch(out[i], keys, inputs[i], kappa);
  }
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
  for (size_t idx = 0; idx < n; ++idx) {
    size_t idx1 = pi[idx];
    uint128_t fx = yacl::crypto::Blake3_128(yacl::SerializeUint128(k ^ idx1));
    out_a[idx] = yacl::crypto::FastRandU128();
    out_b[idx] = fx ^ out_a[idx];
  }
}

static inline block U128ToBlock(uint128_t v) {
  block b;
  static_assert(sizeof(b) == 16);
  std::memcpy(&b, &v, 16);
  return b;
}

static inline __uint128_t BlockToU128(const block& b) {
  uint128_t v;
  static_assert(sizeof(b) == 16);
  std::memcpy(&v, &b, 16);
  return v;
}

static inline secJoin::AltModPrf::KeyType ExpandKey512FromSeed(uint128_t seed) {
  PRNG prng(U128ToBlock(seed));
  secJoin::AltModPrf::KeyType k{};
  for (u64 i = 0; i < k.size(); ++i) { k[i] = prng.get<block>();
}
  return k;
}

struct SsoprfCommStats {
  uint64_t party0_sent_bytes = 0;
  uint64_t party0_recv_bytes = 0;

  uint64_t TotalBytes() const {
    return party0_sent_bytes + party0_recv_bytes;
  }
};

inline SsoprfCommStats RealSsoprf_AltMod_BenchStyleWithSockets(
    coproto::Socket& sockK, coproto::Socket& sockX, std::vector<size_t>& pi,
    __uint128_t k_seed, std::vector<uint128_t>& out_a,
    std::vector<uint128_t>& out_b) {
  const u64 n = static_cast<u64>(pi.size());
  const u64 nt = 1;
  const u64 log_batch = 18;
  const bool useMod2F4Ot = true;
  const auto begin_sent = static_cast<uint64_t>(sockK.bytesSent());
  const auto begin_recv = static_cast<uint64_t>(sockK.bytesReceived());

  out_a.resize(n);
  out_b.resize(n);

  macoro::thread_pool poolK;
  macoro::thread_pool poolX;
  auto eK = poolK.make_work();
  auto eX = poolX.make_work();
  poolK.create_threads(static_cast<std::size_t>(nt));
  poolX.create_threads(static_cast<std::size_t>(nt));

  PRNG prngK(oc::ZeroBlock);
  PRNG prngX(oc::OneBlock);

  // X：把 pi[idx] 编码进 block。若 pi 只到 2^20，这样塞低 64-bit 足够。
  std::vector<block> X(n);
  for (u64 i = 0; i < n; ++i) { X[i] = block(static_cast<u64>(pi[i]), 0);
}

  // Key：由 128-bit seed 扩展成 512-bit key
  secJoin::AltModPrf dm;
  auto kk = ExpandKey512FromSeed(k_seed);
  dm.setKey(kk);

  std::vector<block> shareK(n);
  std::vector<block> shareX(n);



  auto partyX = [&]() -> macoro::task<void> {
    oc::SilentOtExtSender keyOtSender;
    keyOtSender.configure(secJoin::AltModPrf::KeySize);
    std::vector<std::array<block, 2>> sk(secJoin::AltModPrf::KeySize);
    co_await keyOtSender.send(sk, prngX, sockX);

    secJoin::CorGenerator ole1;
    ole1.init(sockX.fork(), prngX, 1, nt, 1ull << log_batch, 1);

    secJoin::AltModWPrfReceiver recver;
    recver.mUseMod2F4Ot = useMod2F4Ot;
    recver.init(n, ole1,
                secJoin::AltModPrfKeyMode::SenderOnly,
                secJoin::AltModPrfInputMode::ReceiverOnly,
                {}, sk);

    co_await macoro::when_all_ready(
        ole1.start(),
        recver.evaluate(X, shareX, sockX, prngX)
    );
  };

  auto partyK = [&]() -> macoro::task<void> {
    // Key 方：KeyOT Receiver，用 key bits 作为 choice 得到 rk
    oc::SilentOtExtReceiver keyOtReceiver;
    keyOtReceiver.configure(secJoin::AltModPrf::KeySize);
    std::vector<block> rk(secJoin::AltModPrf::KeySize);

    oc::BitVector kk_bv;
    kk_bv.append(reinterpret_cast<u8*>(dm.getKey().data()), secJoin::AltModPrf::KeySize);
    co_await keyOtReceiver.receive(kk_bv, rk, prngK, sockK);
    secJoin::CorGenerator ole0;
    ole0.init(sockK.fork(), prngK, 0, nt, 1ull << log_batch, 1);

    // WPRF Sender：只持 key，不持输入
    secJoin::AltModWPrfSender sender;
    sender.mUseMod2F4Ot = useMod2F4Ot;
    sender.init(n, ole0,
                secJoin::AltModPrfKeyMode::SenderOnly,
                secJoin::AltModPrfInputMode::ReceiverOnly,
                dm.getKey(), rk);

    co_await macoro::when_all_ready(
        ole0.start(),
        sender.evaluate({}, shareK, sockK, prngK)
    );
  };

  auto r = coproto::sync_wait(coproto::when_all_ready(
      partyK() | macoro::start_on(poolK),
      partyX() | macoro::start_on(poolX)
  ));
  std::get<0>(r).result();
  std::get<1>(r).result();
  for (u64 i = 0; i < n; ++i) {
    out_a[i] = BlockToU128(shareK[i]);
    out_b[i] = BlockToU128(shareX[i]);
  }
  return {static_cast<uint64_t>(sockK.bytesSent()) - begin_sent,
          static_cast<uint64_t>(sockK.bytesReceived()) - begin_recv};
}

inline SsoprfCommStats RealSsoprf_AltMod_BenchStyle(std::vector<size_t>& pi,
                                  __uint128_t k_seed,
                                  std::vector<uint128_t>& out_a,
                                  std::vector<uint128_t>& out_b) {
  auto sock = coproto::LocalAsyncSocket::makePair();
  return RealSsoprf_AltMod_BenchStyleWithSockets(sock[0], sock[1], pi, k_seed,
                                                 out_a, out_b);
}

inline std::vector<uint128_t> ShuffleWithYacl(const CuckooHash& t_x,
                                              const std::vector<size_t>& perm) {
  size_t n = t_x.cuckoolen_;
  YACL_ENFORCE(perm.size() == n, "Permutation size must match input size");
  std::vector<uint128_t> output(n);
  for (size_t i = 0; i < n; ++i) {
    if (t_x.hash_index_[perm[i]] == 0) {
      output[i] = 0;
    } else {
      output[i] = t_x.bins_[perm[i]];
    }
  }
  return output;
}
