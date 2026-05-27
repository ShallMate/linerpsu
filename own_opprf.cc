#include "examples/linerpsu/own_opprf.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <immintrin.h>
#include <iostream>
#include <thread>
#include <vector>

#include "absl/types/span.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/AES.h"
#include "examples/linerpsu/okvs/baxos.h"
#include "libOTe/Base/BaseOT.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

namespace linerpsu::own_opprf {
namespace {

constexpr size_t kKappa = 128;
constexpr size_t kDefaultHbBits = 64;
constexpr uint64_t kDefaultBinDiv = 4;
using TraceClock = std::chrono::steady_clock;
using TraceTime = TraceClock::time_point;

uint64_t EnvU64(const char* name, uint64_t fallback) {
  const char* value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }
  return std::stoull(value);
}

bool TraceEnabled() { return EnvU64("LINERPSU_OPPRF_TRACE", 0) != 0; }

size_t EffectiveHbBits() {
  const size_t hb_bits = EnvU64("LINERPSU_OPPRF_HB_BITS", kDefaultHbBits);
  YACL_ENFORCE(hb_bits > 0 && hb_bits <= kKappa,
               "LINERPSU_OPPRF_HB_BITS must be in [1, 128]");
  return hb_bits;
}

void TracePhase(const char* role, const char* phase, TraceTime begin) {
  static const bool enabled = TraceEnabled();
  if (!enabled) {
    return;
  }
  const double seconds =
      std::chrono::duration<double>(TraceClock::now() - begin).count();
  std::cerr << "OPPRF_TRACE,role=" << role << ",phase=" << phase
            << ",time_s=" << seconds << std::endl;
}

uint64_t EffectiveBinSize(uint64_t num_items, uint64_t fixed_bin_size) {
  if (fixed_bin_size != 0) {
    return fixed_bin_size;
  }
  if (const uint64_t env_bin_size = EnvU64("LINERPSU_OPPRF_BIN_SIZE", 0)) {
    return env_bin_size;
  }
  const char* env_bin_div = std::getenv("LINERPSU_OPPRF_BIN_DIV");
  if (env_bin_div != nullptr && *env_bin_div != '\0') {
    const uint64_t bin_div = std::max<uint64_t>(1, std::stoull(env_bin_div));
    return std::max<uint64_t>(1, (num_items + bin_div - 1) / bin_div);
  }
  return std::max<uint64_t>(1, (num_items + kDefaultBinDiv - 1) /
                                   kDefaultBinDiv);
}

absl::Span<const uint128_t> AsU128ConstSpan(oc::span<const block> blocks) {
  return absl::MakeConstSpan(
      reinterpret_cast<const uint128_t*>(blocks.data()), blocks.size());
}

block U128ToBlock(uint128_t v) {
  block out;
  static_assert(sizeof(out) == sizeof(v));
  std::memcpy(&out, &v, sizeof(v));
  return out;
}

uint128_t BlockToU128(const block& b) {
  uint128_t out;
  static_assert(sizeof(out) == sizeof(b));
  std::memcpy(&out, &b, sizeof(out));
  return out;
}

void XorToBlocks(absl::Span<const uint128_t> src, oc::span<block> dst) {
  YACL_ENFORCE(src.size() == dst.size(), "span size mismatch");
  for (uint64_t i = 0; i < src.size(); ++i) {
    dst[i] = U128ToBlock(src[i]);
  }
}

uint128_t RandomMaskFromChoices(const oc::BitVector& choices) {
  uint128_t mask = 0;
  for (size_t i = 0; i < choices.size(); ++i) {
    if (choices[i]) {
      mask |= (uint128_t{1} << i);
    }
  }
  return mask;
}

Proto RotReceive(std::array<uint128_t, kKappa>& chosen_keys,
                 uint128_t& choice_mask, size_t hb_bits, PRNG& prng,
                 coproto::Socket& chl) {
  oc::BitVector choices(hb_bits);
  choices.randomize(prng);
  choice_mask = RandomMaskFromChoices(choices);

  std::vector<block> recv_blocks(hb_bits);
  oc::DefaultBaseOT base_ot;
  co_await base_ot.receive(choices, recv_blocks, prng, chl);
  for (size_t i = 0; i < hb_bits; ++i) {
    chosen_keys[i] = BlockToU128(recv_blocks[i]);
  }
}

Proto RotSend(std::array<uint128_t, kKappa>& a_keys,
              std::array<uint128_t, kKappa>& b_keys, size_t hb_bits,
              PRNG& prng, coproto::Socket& chl) {
  std::vector<std::array<block, 2>> send_blocks(hb_bits);
  oc::DefaultBaseOT base_ot;
  co_await base_ot.send(send_blocks, prng, chl);
  for (size_t i = 0; i < hb_bits; ++i) {
    a_keys[i] = BlockToU128(send_blocks[i][0]);
    b_keys[i] = BlockToU128(send_blocks[i][1]);
  }
}

const block* AsBlockPtr(const uint128_t* data) {
  return reinterpret_cast<const block*>(data);
}

void HcircMany(absl::Span<const uint128_t> mask, absl::Span<const uint128_t> point,
               oc::span<block> out) {
  YACL_ENFORCE(mask.size() == point.size(), "Hcirc mask/point size mismatch");
  YACL_ENFORCE(mask.size() == out.size(), "Hcirc output size mismatch");
  const uint64_t n = mask.size();
  oc::mAesFixedKey.hashBlocks(AsBlockPtr(point.data()), n, out.data());
  for (uint64_t i = 0; i < n; ++i) {
    out[i] ^= U128ToBlock(mask[i]);
  }
  oc::mAesFixedKey.hashBlocks(out.data(), n, out.data());
}

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
__attribute__((target("avx512f,avx512bw,vaes"))) uint8_t LsbBits512(
    __m512i state) {
  const uint64_t mask =
      _mm512_movepi8_mask(_mm512_slli_epi16(state, 7));
  return static_cast<uint8_t>(((mask >> 15U) & 1U) |
                              (((mask >> 31U) & 1U) << 1U) |
                              (((mask >> 47U) & 1U) << 2U) |
                              (((mask >> 63U) & 1U) << 3U));
}

__attribute__((target("avx512f,avx512bw,vaes"))) void AesBitBatchVaes512(
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

__attribute__((target("avx512f,avx512bw,vaes"))) void AesBitBatchAAndDVaes512(
    uint128_t& out_a, uint128_t& out_d, const uint128_t* a_keys,
    const uint128_t* b_keys, const uint128_t& input, size_t count) {
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

__attribute__((target("avx2,vaes"))) uint8_t LsbBits256(__m256i state) {
  const uint32_t mask =
      static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_slli_epi16(state, 7)));
  return static_cast<uint8_t>(((mask >> 15U) & 1U) |
                              (((mask >> 31U) & 1U) << 1U));
}

__attribute__((target("avx2,vaes"))) void AesBitBatchVaes256(
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

__attribute__((target("avx2,vaes"))) void AesBitBatchAAndDVaes256(
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

void AesBitBatch(uint128_t& out, const uint128_t* keys, const uint128_t& input,
                 size_t count) {
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

void AesBitBatchAAndD(uint128_t& out_a, uint128_t& out_d,
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

void AesBitBatchMany(uint128_t* out, const uint128_t* keys,
                     const uint128_t* inputs, size_t n,
                     size_t count = kKappa) {
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
  static const bool has_vaes512 =
      EnvU64("LINERPSU_OPPRF_AVX512", 1) != 0 &&
      __builtin_cpu_supports("avx512f") &&
      __builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("vaes");
  if (has_vaes512) {
    for (size_t i = 0; i < n; ++i) {
      AesBitBatchVaes512(out[i], keys, inputs[i], count);
    }
    return;
  }
  static const bool has_vaes256 =
      __builtin_cpu_supports("avx2") && __builtin_cpu_supports("vaes");
  if (has_vaes256) {
    for (size_t i = 0; i < n; ++i) {
      AesBitBatchVaes256(out[i], keys, inputs[i], count);
    }
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    AesBitBatch(out[i], keys, inputs[i], count);
  }
}

void AesBitBatchAAndDMany(uint128_t* out_a, uint128_t* out_d,
                          const uint128_t* a_keys, const uint128_t* b_keys,
                          const uint128_t* inputs, size_t n,
                          size_t count = kKappa) {
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
  static const bool has_vaes512 =
      EnvU64("LINERPSU_OPPRF_AVX512", 1) != 0 &&
      __builtin_cpu_supports("avx512f") &&
      __builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("vaes");
  if (has_vaes512) {
    for (size_t i = 0; i < n; ++i) {
      AesBitBatchAAndDVaes512(out_a[i], out_d[i], a_keys, b_keys, inputs[i],
                              count);
    }
    return;
  }
  static const bool has_vaes256 =
      __builtin_cpu_supports("avx2") && __builtin_cpu_supports("vaes");
  if (has_vaes256) {
    for (size_t i = 0; i < n; ++i) {
      AesBitBatchAAndDVaes256(out_a[i], out_d[i], a_keys, b_keys, inputs[i],
                              count);
    }
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    AesBitBatchAAndD(out_a[i], out_d[i], a_keys, b_keys, inputs[i], count);
  }
}

void EvalHbMany(uint128_t* out, const std::array<uint128_t, kKappa>& keys,
                absl::Span<const uint128_t> inputs, size_t hb_bits,
                uint64_t num_threads) {
  num_threads = std::max<uint64_t>(1, num_threads);
  if (num_threads == 1 || inputs.size() < (1 << 14)) {
    AesBitBatchMany(out, keys.data(), inputs.data(), inputs.size(), hb_bits);
    return;
  }

  std::vector<std::thread> threads;
  threads.reserve(num_threads);
  for (uint64_t t = 0; t < num_threads; ++t) {
    const uint64_t begin = (inputs.size() * t) / num_threads;
    const uint64_t end = (inputs.size() * (t + 1)) / num_threads;
    threads.emplace_back([&, begin, end] {
      AesBitBatchMany(out + begin, keys.data(), inputs.data() + begin,
                      end - begin, hb_bits);
    });
  }
  for (auto& th : threads) {
    th.join();
  }
}

void EvalHbAAndDMany(uint128_t* out_a, uint128_t* out_d,
                     const std::array<uint128_t, kKappa>& a_keys,
                     const std::array<uint128_t, kKappa>& b_keys,
                     absl::Span<const uint128_t> inputs, size_t hb_bits,
                     uint64_t num_threads) {
  num_threads = std::max<uint64_t>(1, num_threads);
  if (num_threads == 1 || inputs.size() < (1 << 14)) {
    AesBitBatchAAndDMany(out_a, out_d, a_keys.data(), b_keys.data(),
                         inputs.data(), inputs.size(), hb_bits);
    return;
  }

  std::vector<std::thread> threads;
  threads.reserve(num_threads);
  for (uint64_t t = 0; t < num_threads; ++t) {
    const uint64_t begin = (inputs.size() * t) / num_threads;
    const uint64_t end = (inputs.size() * (t + 1)) / num_threads;
    threads.emplace_back([&, begin, end] {
      AesBitBatchAAndDMany(out_a + begin, out_d + begin, a_keys.data(),
                           b_keys.data(), inputs.data() + begin, end - begin,
                           hb_bits);
    });
  }
  for (auto& th : threads) {
    th.join();
  }
}

}  // namespace

Proto Sender::GenerateMasks(oc::span<const block> keys, oc::span<block> masks,
                            PRNG& prng, coproto::Socket& chl,
                            uint64_t num_threads) {
  setTimePoint("OwnOpprfSender::mask begin");
  YACL_ENFORCE(keys.size() == masks.size(), "key/mask size mismatch");
  YACL_ENFORCE(!keys.empty(), "empty OPPRF input");
  num_threads = std::max<uint64_t>(1, num_threads);

  uint64_t receiver_size = 0;
  uint128_t rho0 = 0;
  co_await chl.recv(receiver_size);
  co_await chl.recv(rho0);

  okvs::Baxos receiver_baxos;
  receiver_baxos.Init(receiver_size,
                      EffectiveBinSize(receiver_size, fixed_bin_size_), 3, ssp_,
                      okvs::PaxosParam::DenseType::GF128, rho0);

  const size_t hb_bits = EffectiveHbBits();
  std::array<uint128_t, kKappa> c_keys;
  uint128_t choice_mask = 0;
  auto phase_begin = TraceClock::now();
  co_await RotReceive(c_keys, choice_mask, hb_bits, prng, chl);
  TracePhase("sender", "rot", phase_begin);
  setTimePoint("OwnOpprfSender::rot");

  const auto key_u128 = AsU128ConstSpan(keys);
  std::vector<uint128_t> c_bits(keys.size());
  phase_begin = TraceClock::now();
  EvalHbMany(c_bits.data(), c_keys, key_u128, hb_bits, num_threads);
  TracePhase("sender", "hb", phase_begin);

  std::vector<uint128_t> p0(receiver_baxos.size());
  co_await chl.recv(p0);

  std::vector<uint128_t> decoded_d(keys.size());
  phase_begin = TraceClock::now();
  receiver_baxos.Decode(key_u128, absl::MakeSpan(decoded_d),
                        absl::MakeSpan(p0), num_threads);
  TracePhase("sender", "decode_p0", phase_begin);

  phase_begin = TraceClock::now();
  for (uint64_t i = 0; i < keys.size(); ++i) {
    c_bits[i] ^= decoded_d[i] & choice_mask;
  }
  HcircMany(absl::MakeConstSpan(c_bits), key_u128, masks);
  TracePhase("sender", "hcirc", phase_begin);
  setTimePoint("OwnOpprfSender::mask end");
}

Proto Receiver::GenerateMasks(oc::span<const block> keys, oc::span<block> masks,
                              PRNG& prng, coproto::Socket& chl,
                              uint64_t num_threads) {
  setTimePoint("OwnOpprfReceiver::mask begin");
  YACL_ENFORCE(keys.size() == masks.size(), "key/mask size mismatch");
  YACL_ENFORCE(!keys.empty(), "empty OPPRF input");
  num_threads = std::max<uint64_t>(1, num_threads);

  const uint64_t receiver_size = keys.size();
  const uint128_t rho0 = BlockToU128(prng.get());
  co_await chl.send(coproto::copy(receiver_size));
  co_await chl.send(coproto::copy(rho0));

  const size_t hb_bits = EffectiveHbBits();
  std::array<uint128_t, kKappa> a_keys;
  std::array<uint128_t, kKappa> b_keys;
  auto phase_begin = TraceClock::now();
  co_await RotSend(a_keys, b_keys, hb_bits, prng, chl);
  TracePhase("receiver", "rot", phase_begin);
  setTimePoint("OwnOpprfReceiver::rot");

  const auto key_u128 = AsU128ConstSpan(keys);
  std::vector<uint128_t> a_bits(keys.size());
  std::vector<uint128_t> d_bits(keys.size());
  phase_begin = TraceClock::now();
  EvalHbAAndDMany(a_bits.data(), d_bits.data(), a_keys, b_keys, key_u128,
                  hb_bits, num_threads);
  TracePhase("receiver", "hb_a_d", phase_begin);

  okvs::Baxos receiver_baxos;
  receiver_baxos.Init(receiver_size,
                      EffectiveBinSize(receiver_size, fixed_bin_size_), 3, ssp_,
                      okvs::PaxosParam::DenseType::GF128, rho0);
  std::vector<uint128_t> p0(receiver_baxos.size());
  phase_begin = TraceClock::now();
  receiver_baxos.Solve(key_u128, absl::MakeSpan(d_bits), absl::MakeSpan(p0),
                       nullptr, num_threads);
  TracePhase("receiver", "solve_p0", phase_begin);
  co_await chl.send(coproto::copy(p0));

  phase_begin = TraceClock::now();
  HcircMany(absl::MakeConstSpan(a_bits), key_u128, masks);
  TracePhase("receiver", "hcirc", phase_begin);

  setTimePoint("OwnOpprfReceiver::mask end");
}

Proto Sender::Send(oc::span<const block> keys, oc::span<const block> values,
                   PRNG& prng, coproto::Socket& chl,
                   uint64_t num_threads) {
  setTimePoint("OwnOpprfSender::send begin");
  YACL_ENFORCE(keys.size() == values.size(), "key/value size mismatch");

  std::vector<block> masks(keys.size());
  co_await GenerateMasks(keys, oc::span<block>(masks.data(), masks.size()),
                         prng, chl, num_threads);

  const auto key_u128 = AsU128ConstSpan(keys);
  const auto value_u128 = AsU128ConstSpan(values);
  const auto mask_u128 =
      AsU128ConstSpan(oc::span<const block>(masks.data(), masks.size()));

  std::vector<uint128_t> p1_values(keys.size());
  for (uint64_t i = 0; i < keys.size(); ++i) {
    p1_values[i] = value_u128[i] ^ mask_u128[i];
  }

  const uint128_t rho1 = BlockToU128(prng.get());
  okvs::Baxos sender_baxos;
  sender_baxos.Init(keys.size(),
                    EffectiveBinSize(keys.size(), fixed_bin_size_), 3, ssp_,
                    okvs::PaxosParam::DenseType::GF128, rho1);
  std::vector<uint128_t> p1(sender_baxos.size());
  sender_baxos.Solve(key_u128, absl::MakeSpan(p1_values), absl::MakeSpan(p1),
                     nullptr, std::max<uint64_t>(1, num_threads));

  co_await chl.send(coproto::copy(rho1));
  co_await chl.send(coproto::copy(p1));
  setTimePoint("OwnOpprfSender::send end");
}

Proto Receiver::Receive(uint64_t sender_size, oc::span<const block> keys,
                        oc::span<block> outputs, PRNG& prng,
                        coproto::Socket& chl, uint64_t num_threads) {
  setTimePoint("OwnOpprfReceiver::receive begin");
  YACL_ENFORCE(keys.size() == outputs.size(), "key/output size mismatch");

  std::vector<block> masks(keys.size());
  co_await GenerateMasks(keys, oc::span<block>(masks.data(), masks.size()),
                         prng, chl, num_threads);

  uint128_t rho1 = 0;
  co_await chl.recv(rho1);
  okvs::Baxos sender_baxos;
  sender_baxos.Init(sender_size,
                    EffectiveBinSize(sender_size, fixed_bin_size_), 3, ssp_,
                    okvs::PaxosParam::DenseType::GF128, rho1);
  std::vector<uint128_t> p1(sender_baxos.size());
  co_await chl.recv(p1);

  const auto key_u128 = AsU128ConstSpan(keys);
  const auto mask_u128 =
      AsU128ConstSpan(oc::span<const block>(masks.data(), masks.size()));
  std::vector<uint128_t> decoded(keys.size());
  sender_baxos.Decode(key_u128, absl::MakeSpan(decoded), absl::MakeSpan(p1),
                      std::max<uint64_t>(1, num_threads));
  for (uint64_t i = 0; i < decoded.size(); ++i) {
    decoded[i] ^= mask_u128[i];
  }
  XorToBlocks(absl::MakeConstSpan(decoded), outputs);
  setTimePoint("OwnOpprfReceiver::receive end");
}

}  // namespace linerpsu::own_opprf
