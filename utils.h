#pragma once

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
#include <cryptoTools/Common/block.h>
#include <iostream>
#include <chrono>
#include <secureJoin/secure-join/Perm/PprfPermGen.h>
#include "secureJoin/secure-join/Perm/PermCorrelation.h"
#include "secureJoin/secure-join/Perm/AltModPerm.h"
#include "secureJoin/secure-join/Perm/Permutation.h"
#include "secureJoin/secure-join/CorGenerator/CorGenerator.h"
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


inline size_t RealSsoprf_AltMod_BenchStyle(std::vector<size_t>& pi,
                                  __uint128_t k_seed,
                                  std::vector<uint128_t>& out_a,
                                  std::vector<uint128_t>& out_b) {
  const u64 n = static_cast<u64>(pi.size());
  const u64 nt = 1;
  const u64 log_batch = 18;
  const bool useMod2F4Ot = true;

  out_a.resize(n);
  out_b.resize(n);

  auto sock = coproto::LocalAsyncSocket::makePair();
  macoro::thread_pool poolK;
  macoro::thread_pool poolX;
  auto eK = poolK.make_work();
  auto eX = poolX.make_work();
  poolK.create_threads(static_cast<std::size_t>(nt));
  poolX.create_threads(static_cast<std::size_t>(nt));

  sock[0].setExecutor(poolK); sock[1].setExecutor(poolX);


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

  //oc::Timer timer;
  //auto t0 = timer.setTimePoint("begin");

  auto partyX = [&]() -> macoro::task<void> {
    // X 方：KeyOT Sender 生成 sk
    oc::SilentOtExtSender keyOtSender;
    keyOtSender.configure(secJoin::AltModPrf::KeySize);
    std::vector<std::array<block, 2>> sk(secJoin::AltModPrf::KeySize);
    co_await keyOtSender.send(sk, prngX, sock[1]);

    // OLE（role=1）。最后一个参数请先对齐你旧 benchmark：你旧代码是 1。
    secJoin::CorGenerator ole1;
    ole1.init(sock[1].fork(), prngX, 1, nt, 1ull << log_batch, 1);

    // WPRF Receiver：只持输入 X，不持 key
    secJoin::AltModWPrfReceiver recver;
    recver.mUseMod2F4Ot = useMod2F4Ot;
    recver.init(n, ole1,
                secJoin::AltModPrfKeyMode::SenderOnly,
                secJoin::AltModPrfInputMode::ReceiverOnly,
                {}, sk);

    co_await macoro::when_all_ready(
        ole1.start(),
        recver.evaluate(X, shareX, sock[1], prngX)
    );
  };

  auto partyK = [&]() -> macoro::task<void> {
    // Key 方：KeyOT Receiver，用 key bits 作为 choice 得到 rk
    oc::SilentOtExtReceiver keyOtReceiver;
    keyOtReceiver.configure(secJoin::AltModPrf::KeySize);
    std::vector<block> rk(secJoin::AltModPrf::KeySize);

    oc::BitVector kk_bv;
    kk_bv.append(reinterpret_cast<u8*>(dm.getKey().data()), secJoin::AltModPrf::KeySize);
    co_await keyOtReceiver.receive(kk_bv, rk, prngK, sock[0]);
    secJoin::CorGenerator ole0;
    ole0.init(sock[0].fork(), prngK, 0, nt, 1ull << log_batch, 1);

    // WPRF Sender：只持 key，不持输入
    secJoin::AltModWPrfSender sender;
    sender.mUseMod2F4Ot = useMod2F4Ot;
    sender.init(n, ole0,
                secJoin::AltModPrfKeyMode::SenderOnly,
                secJoin::AltModPrfInputMode::ReceiverOnly,
                dm.getKey(), rk);

    co_await macoro::when_all_ready(
        ole0.start(),
        sender.evaluate({}, shareK, sock[0], prngK)
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
  size_t bytes = static_cast<size_t>(sock[0].bytesSent() + sock[0].bytesReceived());
  return bytes;
}


inline std::vector<uint128_t> ShuffleWithYacl(CuckooHash t_x,
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
