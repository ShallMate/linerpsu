#include "examples/linerpsu/rr22_oprf.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include "absl/types/span.h"
#include "examples/linerpsu/okvs/baxos.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

namespace linerpsu::rr22_oprf {
namespace {

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

void TracePhase(const char* role, const char* phase, TraceTime begin) {
  static const bool enabled = TraceEnabled();
  if (!enabled) {
    return;
  }
  const double seconds =
      std::chrono::duration<double>(TraceClock::now() - begin).count();
  std::cerr << "RR22_OPRF_TRACE,role=" << role << ",phase=" << phase
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

absl::Span<uint128_t> AsU128Span(block* blocks, uint64_t size) {
  return absl::MakeSpan(reinterpret_cast<uint128_t*>(blocks), size);
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

block* AsBlockPtr(uint128_t* data) {
  return reinterpret_cast<block*>(data);
}

void BlocksToU128(oc::span<const block> src, absl::Span<uint128_t> dst) {
  YACL_ENFORCE(src.size() == dst.size(), "span size mismatch");
  for (uint64_t i = 0; i < src.size(); ++i) {
    dst[i] = BlockToU128(src[i]);
  }
}

void U128ToBlocks(absl::Span<const uint128_t> src, oc::span<block> dst) {
  YACL_ENFORCE(src.size() == dst.size(), "span size mismatch");
  for (uint64_t i = 0; i < src.size(); ++i) {
    dst[i] = U128ToBlock(src[i]);
  }
}

void FixedKeyHashToU128(oc::span<const block> input,
                        std::vector<uint128_t>& output) {
  output.resize(input.size());
  std::vector<block> hashed(input.size());
  oc::mAesFixedKey.hashBlocks(input.data(), input.size(), hashed.data());
  BlocksToU128(oc::span<const block>(hashed.data(), hashed.size()),
               absl::MakeSpan(output));
}

void FinalizeMasks(oc::span<block> masks) {
  oc::mAesFixedKey.hashBlocks(masks.data(), masks.size(), masks.data());
}

void ApplyRr22SenderEval(absl::Span<const uint128_t> decoded,
                         oc::span<const block> point_hashes,
                         const block& delta, oc::span<block> masks) {
  YACL_ENFORCE(decoded.size() == point_hashes.size(), "span size mismatch");
  YACL_ENFORCE(decoded.size() == masks.size(), "span size mismatch");
  for (uint64_t i = 0; i < decoded.size(); ++i) {
    masks[i] = U128ToBlock(decoded[i]) ^ delta.gf128Mul(point_hashes[i]);
  }
  FinalizeMasks(masks);
}

void UseTungstenIfRequested(
    oc::SilentVoleSender<block, block, oc::CoeffCtxGF128>& vole) {
  if (EnvU64("LINERPSU_RR22_TUNGSTEN", 0) != 0) {
    vole.mMultType = oc::MultType::Tungsten;
  }
}

void UseTungstenIfRequested(
    oc::SilentVoleReceiver<block, block, oc::CoeffCtxGF128>& vole) {
  if (EnvU64("LINERPSU_RR22_TUNGSTEN", 0) != 0) {
    vole.mMultType = oc::MultType::Tungsten;
  }
}

}  // namespace

Proto Sender::GenerateMasks(oc::span<const block> keys, oc::span<block> masks,
                            PRNG& prng, coproto::Socket& chl,
                            uint64_t num_threads) {
  setTimePoint("RR22Sender::mask begin");
  YACL_ENFORCE(keys.size() == masks.size(), "key/mask size mismatch");
  YACL_ENFORCE(!keys.empty(), "empty OPRF input");
  num_threads = std::max<uint64_t>(1, num_threads);

  uint64_t receiver_size = 0;
  uint128_t rho = 0;
  co_await chl.recv(receiver_size);
  co_await chl.recv(rho);

  okvs::Baxos receiver_baxos;
  receiver_baxos.Init(receiver_size,
                      EffectiveBinSize(receiver_size, fixed_bin_size_), 3, ssp_,
                      okvs::PaxosParam::DenseType::GF128, rho);

  block delta = prng.get();
  oc::SilentVoleSender<block, block, oc::CoeffCtxGF128> vole_sender;
  UseTungstenIfRequested(vole_sender);
  auto fork = chl.fork();
  auto vole_task =
      vole_sender
          .silentSendInplace(delta, receiver_baxos.size(), prng, fork)
      | macoro::make_eager();

  std::vector<uint128_t> p(receiver_baxos.size());
  co_await chl.recv(p);

  auto phase_begin = TraceClock::now();
  co_await vole_task;
  TracePhase("sender", "vole", phase_begin);
  YACL_ENFORCE(vole_sender.mB.size() == p.size(), "VOLE size mismatch");

  phase_begin = TraceClock::now();
  block* p_blocks = AsBlockPtr(p.data());
  for (uint64_t i = 0; i < p.size(); ++i) {
    p_blocks[i] = vole_sender.mB[i] ^ delta.gf128Mul(p_blocks[i]);
  }
  TracePhase("sender", "gf128_mul", phase_begin);

  const auto key_u128 = AsU128ConstSpan(keys);
  std::vector<uint128_t> decoded(keys.size());
  phase_begin = TraceClock::now();
  receiver_baxos.Decode(key_u128, absl::MakeSpan(decoded),
                        absl::MakeSpan(p), num_threads);
  TracePhase("sender", "decode", phase_begin);

  std::vector<block> point_hashes(keys.size());
  phase_begin = TraceClock::now();
  oc::mAesFixedKey.hashBlocks(keys.data(), keys.size(), point_hashes.data());
  ApplyRr22SenderEval(absl::MakeConstSpan(decoded),
                      oc::span<const block>(point_hashes.data(),
                                            point_hashes.size()),
                      delta, masks);
  TracePhase("sender", "hash", phase_begin);

  setTimePoint("RR22Sender::mask end");
}

Proto Receiver::GenerateMasks(oc::span<const block> keys, oc::span<block> masks,
                              PRNG& prng, coproto::Socket& chl,
                              uint64_t num_threads) {
  setTimePoint("RR22Receiver::mask begin");
  YACL_ENFORCE(keys.size() == masks.size(), "key/mask size mismatch");
  YACL_ENFORCE(!keys.empty(), "empty OPRF input");
  num_threads = std::max<uint64_t>(1, num_threads);

  const uint64_t receiver_size = keys.size();
  const uint128_t rho = BlockToU128(prng.get());
  co_await chl.send(coproto::copy(receiver_size));
  co_await chl.send(coproto::copy(rho));

  okvs::Baxos receiver_baxos;
  receiver_baxos.Init(receiver_size,
                      EffectiveBinSize(receiver_size, fixed_bin_size_), 3, ssp_,
                      okvs::PaxosParam::DenseType::GF128, rho);

  oc::SilentVoleReceiver<block, block, oc::CoeffCtxGF128> vole_receiver;
  UseTungstenIfRequested(vole_receiver);
  auto fork = chl.fork();
  auto vole_task =
      vole_receiver.silentReceiveInplace(receiver_baxos.size(), prng, fork)
      | macoro::make_eager();

  const auto key_u128 = AsU128ConstSpan(keys);
  std::vector<uint128_t> point_hashes;
  auto phase_begin = TraceClock::now();
  FixedKeyHashToU128(keys, point_hashes);
  TracePhase("receiver", "hash_points", phase_begin);

  std::vector<uint128_t> p(receiver_baxos.size());
  phase_begin = TraceClock::now();
  receiver_baxos.Solve(key_u128, absl::MakeSpan(point_hashes),
                       absl::MakeSpan(p), nullptr, num_threads);
  TracePhase("receiver", "solve", phase_begin);

  phase_begin = TraceClock::now();
  co_await vole_task;
  TracePhase("receiver", "vole", phase_begin);
  YACL_ENFORCE(vole_receiver.mA.size() == receiver_baxos.size(),
               "VOLE A size mismatch");
  YACL_ENFORCE(vole_receiver.mC.size() == receiver_baxos.size(),
               "VOLE C size mismatch");

  phase_begin = TraceClock::now();
  block* p_blocks = AsBlockPtr(p.data());
  for (uint64_t i = 0; i < p.size(); ++i) {
    p_blocks[i] = p_blocks[i] ^ vole_receiver.mC[i];
  }
  TracePhase("receiver", "xor_c", phase_begin);

  co_await chl.send(coproto::copy(p));

  std::vector<uint128_t> decoded(keys.size());
  phase_begin = TraceClock::now();
  receiver_baxos.Decode(
      key_u128, absl::MakeSpan(decoded),
      AsU128Span(vole_receiver.mA.data(), vole_receiver.mA.size()), num_threads);
  U128ToBlocks(absl::MakeConstSpan(decoded), masks);
  FinalizeMasks(masks);
  TracePhase("receiver", "decode_hash", phase_begin);

  setTimePoint("RR22Receiver::mask end");
}

}  // namespace linerpsu::rr22_oprf
