#pragma once

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <future>
#include <string>
#include <utility>
#include <vector>

#include "examples/linerpsu/local_comm_stats.h"
#include "examples/linerpsu/peqt_gmw.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

namespace linerpsu {

constexpr size_t kDefaultPeqtBitWidth = 64;

struct PeqtShares {
  std::vector<bool> sender;
  std::vector<bool> receiver;
  double offline_seconds = 0.0;
  double online_seconds = 0.0;
  psu::local_comm_stats::CommStats offline_comm;
  psu::local_comm_stats::CommStats online_comm;
};

inline psu::local_comm_stats::CommStats MakePeqtSetupCommStats(
    const psu::peqt::PreparedCircuitGmwState& sender,
    const psu::peqt::PreparedCircuitGmwState& receiver) {
  psu::local_comm_stats::CommStats stats;
  stats.sent[0] = sender.setup_sent_bytes;
  stats.recv[0] = sender.setup_recv_bytes;
  stats.sent[1] = receiver.setup_sent_bytes;
  stats.recv[1] = receiver.setup_recv_bytes;
  return stats;
}

inline std::vector<uint128_t> BuildPermutedPeqtReceiverInputs(
    const std::vector<uint128_t>& sender_masks,
    const std::vector<uint128_t>& receiver_masks,
    const std::vector<size_t>& permutation) {
  const size_t n = permutation.size();
  YACL_ENFORCE(sender_masks.size() == n,
               "sender mask size mismatch: got {}, expect {}",
               sender_masks.size(), n);
  YACL_ENFORCE(receiver_masks.size() >= n,
               "receiver mask size mismatch: got {}, expect at least {}",
               receiver_masks.size(), n);

  std::vector<uint128_t> inputs(n);
  for (size_t i = 0; i < n; ++i) {
    const size_t permuted_idx = permutation[i];
    YACL_ENFORCE(permuted_idx < receiver_masks.size(),
                 "permutation index {} out of range {}", permuted_idx,
                 receiver_masks.size());
    inputs[i] = receiver_masks[permuted_idx] ^ sender_masks[i];
  }
  return inputs;
}

inline std::vector<bool> ToBoolShares(const std::vector<uint8_t>& shares) {
  std::vector<bool> out(shares.size());
  for (size_t i = 0; i < shares.size(); ++i) {
    out[i] = (shares[i] & 1U) != 0U;
  }
  return out;
}

inline PeqtShares RunUpsuGmwPermutedPeqt(
    const std::vector<uint128_t>& sender_inputs,
    const std::vector<uint128_t>& sender_masks,
    const std::vector<uint128_t>& receiver_masks,
    const std::vector<size_t>& permutation,
    size_t bit_width = kDefaultPeqtBitWidth,
    const std::string& tag_prefix = "LINERPSU_PEQT") {
  const auto receiver_inputs =
      BuildPermutedPeqtReceiverInputs(sender_masks, receiver_masks, permutation);
  YACL_ENFORCE(sender_inputs.size() == receiver_inputs.size(),
               "PEQT input size mismatch: sender={}, receiver={}",
               sender_inputs.size(), receiver_inputs.size());

  PeqtShares result;

  const auto offline_begin = std::chrono::high_resolution_clock::now();
  auto sender_prepare = std::async(std::launch::async, [&] {
    return psu::peqt::PrepareEqU128Vec2PCPreRot(
        0, sender_inputs.size(), bit_width, tag_prefix);
  });
  auto receiver_prepare = std::async(std::launch::async, [&] {
    return psu::peqt::PrepareEqU128Vec2PCPreRot(
        1, receiver_inputs.size(), bit_width, tag_prefix);
  });
  auto sender_prepared = sender_prepare.get();
  auto receiver_prepared = receiver_prepare.get();
  const auto offline_end = std::chrono::high_resolution_clock::now();
  result.offline_seconds =
      std::chrono::duration<double>(offline_end - offline_begin).count();
  result.offline_comm =
      MakePeqtSetupCommStats(sender_prepared, receiver_prepared);

  psu::local_comm_stats::Reset();
  const auto online_begin = std::chrono::high_resolution_clock::now();
  auto sender_run = std::async(std::launch::async, [&] {
    return psu::peqt::RunPreparedEqU128Vec2PCPreRot(
        sender_prepared, sender_inputs, tag_prefix);
  });
  auto receiver_run = std::async(std::launch::async, [&] {
    return psu::peqt::RunPreparedEqU128Vec2PCPreRot(
        receiver_prepared, receiver_inputs, tag_prefix);
  });
  result.sender = ToBoolShares(sender_run.get());
  result.receiver = ToBoolShares(receiver_run.get());
  const auto online_end = std::chrono::high_resolution_clock::now();
  result.online_seconds =
      std::chrono::duration<double>(online_end - online_begin).count();
  result.online_comm = psu::local_comm_stats::Snapshot();
  return result;
}

}  // namespace linerpsu
