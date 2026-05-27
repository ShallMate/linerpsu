#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <future>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "coproto/Socket/AsioSocket.h"
#include "coproto/coproto.h"
#include "examples/linerpsu/GMW/Circuit.h"
#include "examples/linerpsu/GMW/Gmw.h"
#include "examples/linerpsu/coproto_asio_globals.h"
#include "examples/linerpsu/debug_logging.h"
#include "examples/linerpsu/local_comm_stats.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/utils/parallel.h"

namespace psu::peqt {

using Block = uint128_t;

inline std::optional<size_t> ParseSizeEnv(const char* name) {
  if (const char* env = std::getenv(name)) {
    char* end = nullptr;
    auto parsed = std::strtoull(env, &end, 10);
    if (end != env && *end == '\0' && parsed > 0) {
      return static_cast<size_t>(parsed);
    }
  }
  return std::nullopt;
}

inline size_t CeilDivSize(size_t value, size_t divisor) {
  YACL_ENFORCE(divisor > 0, "divisor must be positive");
  return value / divisor + static_cast<size_t>((value % divisor) != 0);
}

inline size_t RoundUpTo128(size_t value) {
  return CeilDivSize(value, static_cast<size_t>(128)) * 128;
}

inline size_t SaturatingMulSize(size_t lhs, size_t rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  const size_t max = static_cast<size_t>(-1);
  if (lhs > max / rhs) {
    return max;
  }
  return lhs * rhs;
}

inline void PeqtDebugLog(const std::string& message) {
  debug::LogKv("peqt", message);
}

struct ParsedPeqtAddress {
  std::string host;
  uint16_t port = 0;
};

inline ParsedPeqtAddress ParsePeqtAddress(const std::string& address) {
  const auto pos = address.rfind(':');
  YACL_ENFORCE(pos != std::string::npos,
               "peqt address must be host:port, got={}", address);
  ParsedPeqtAddress parsed;
  parsed.host = address.substr(0, pos);
  const auto port_str = address.substr(pos + 1);
  int port = 0;
  try {
    port = std::stoi(port_str);
  } catch (const std::exception&) {
    YACL_THROW("invalid peqt port in address: {}", address);
  }
  YACL_ENFORCE(port > 0 && port <= 65535, "invalid peqt port={}", port);
  parsed.port = static_cast<uint16_t>(port);
  return parsed;
}

inline std::string PeqtBaseAddress() {
  if (const char* env = std::getenv("PSU_PEQT_ADDRESS")) {
    return std::string(env);
  }
  return "127.0.0.1:13005";
}

inline std::string MakePeqtBatchAddress(size_t batch_idx) {
  auto parsed = ParsePeqtAddress(PeqtBaseAddress());
  const uint32_t port =
      static_cast<uint32_t>(parsed.port) + static_cast<uint32_t>(batch_idx);
  YACL_ENFORCE(port <= 65535,
               "peqt batch port overflow, base={}, batch_idx={}",
               PeqtBaseAddress(), batch_idx);
  std::ostringstream oss;
  oss << parsed.host << ":" << port;
  return oss.str();
}

inline coproto::AsioSocket ConnectPeqtSocket(const std::string& address,
                                             bool is_listener) {
  {
    std::ostringstream oss;
    oss << "connect socket start address=" << address
        << ", is_listener=" << is_listener;
    PeqtDebugLog(oss.str());
  }
  if (is_listener) {
    auto sock = coproto::asioConnect(address, true);
    PeqtDebugLog("connect socket done address=" + address +
                 ", is_listener=1");
    return sock;
  }

  constexpr int kMaxRetry = 200;
  for (int attempt = 0; attempt < kMaxRetry; ++attempt) {
    try {
      auto sock = coproto::asioConnect(address, false);
      std::ostringstream oss;
      oss << "connect socket done address=" << address << ", is_listener=0"
          << ", attempts=" << (attempt + 1);
      PeqtDebugLog(oss.str());
      return sock;
    } catch (const std::exception& e) {
      if (attempt == 0 || (attempt + 1) % 20 == 0) {
        std::ostringstream oss;
        oss << "connect socket retry address=" << address
            << ", next_attempt=" << (attempt + 2)
            << ", error=" << e.what();
        PeqtDebugLog(oss.str());
      }
      if (attempt + 1 == kMaxRetry) {
        throw;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  YACL_THROW("failed to connect peqt socket: {}", address);
}

inline size_t GmwThreadCount() {
  static const size_t thread_count = [] {
    if (auto parsed = ParseSizeEnv("PSU_PEQT_GMW_THREADS")) {
      return *parsed;
    }
    return static_cast<size_t>(1);
  }();
  return thread_count;
}

inline size_t PeqtBatchItemCount() {
  static const size_t batch_items = [] {
    if (auto parsed = ParseSizeEnv("PSU_PEQT_BATCH_ITEMS")) {
      return *parsed;
    }
    return static_cast<size_t>(1) << 21;
  }();
  return batch_items;
}

inline size_t PeqtParallelBatchCount() {
  static const size_t parallel_batches = [] {
    if (auto parsed = ParseSizeEnv("PSU_PEQT_PARALLEL_BATCHES")) {
      return *parsed;
    }
    return static_cast<size_t>(1);
  }();
  return parallel_batches;
}

inline std::optional<size_t> FixedGmwTripleBatchSize() {
  static const std::optional<size_t> batch_size =
      ParseSizeEnv("PSU_PEQT_GMW_TRIPLE_BATCH");
  return batch_size;
}

inline size_t GmwTripleMaxBatches() {
  static const size_t max_batches = [] {
    if (auto parsed = ParseSizeEnv("PSU_PEQT_GMW_MAX_TRIPLE_BATCHES")) {
      return *parsed;
    }
    return static_cast<size_t>(16);
  }();
  return max_batches;
}

inline size_t GmwTripleMaxBatchBytes() {
  static const size_t max_bytes = [] {
    if (auto parsed = ParseSizeEnv("PSU_PEQT_GMW_MAX_BATCH_BYTES")) {
      return *parsed;
    }
    return static_cast<size_t>(256) << 20;
  }();
  return max_bytes;
}

inline size_t GmwTripleMemoryCappedBatchSize() {
  constexpr size_t kSenderOtBytesPerItem = sizeof(std::array<Block, 2>);
  return std::max<size_t>(1,
                          GmwTripleMaxBatchBytes() / kSenderOtBytesPerItem);
}

inline size_t EstimateGmwTripleOtCount(size_t n,
                                       const volePSI::BetaCircuit& cir) {
  const size_t word_cols = CeilDivSize(n, static_cast<size_t>(128));
  const size_t packed_rows =
      SaturatingMulSize(word_cols, static_cast<size_t>(128));
  const size_t gates = static_cast<size_t>(cir.mNonlinearGateCount);
  return SaturatingMulSize(SaturatingMulSize(packed_rows, gates),
                           static_cast<size_t>(2));
}

inline size_t GmwTripleBatchSizeFor(size_t n,
                                    const volePSI::BetaCircuit& cir) {
  if (auto fixed = FixedGmwTripleBatchSize()) {
    return RoundUpTo128(*fixed);
  }

  const size_t estimated_ots = EstimateGmwTripleOtCount(n, cir);
  if (estimated_ots == 0) {
    return static_cast<size_t>(1);
  }

  constexpr size_t kMinUsefulBatch = static_cast<size_t>(1) << 20;
  const size_t by_round_cap = std::max(
      kMinUsefulBatch, CeilDivSize(estimated_ots, GmwTripleMaxBatches()));
  const size_t by_memory_cap =
      std::max<size_t>(1, GmwTripleMemoryCappedBatchSize());
  return RoundUpTo128(std::min(by_round_cap, by_memory_cap));
}

inline volePSI::Matrix<volePSI::u8> MakeInputMatrix(const uint128_t* my_vec,
                                                    size_t n,
                                                    size_t bit_width) {
  const size_t num_bytes = (bit_width + 7) / 8;
  volePSI::Matrix<volePSI::u8> input;
  input.resize(n, num_bytes);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      auto row = input[static_cast<size_t>(idx)];
      std::memcpy(row.data(), &my_vec[idx], num_bytes);
      if ((bit_width & 7U) != 0U) {
        row[num_bytes - 1] &=
            static_cast<uint8_t>((1U << (bit_width & 7U)) - 1U);
      }
    }
  });
  return input;
}

inline void FlushLocalSocket(coproto::Socket& sock) {
  coproto::sync_wait(sock.flush());
}

struct SocketBytesSnapshot {
  uint64_t sent = 0;
  uint64_t recv = 0;
};

inline SocketBytesSnapshot TakeSocketBytesSnapshot(coproto::Socket& sock) {
  return {static_cast<uint64_t>(sock.bytesSent()),
          static_cast<uint64_t>(sock.bytesReceived())};
}

inline SocketBytesSnapshot DiffSocketBytes(const SocketBytesSnapshot& begin,
                                          const SocketBytesSnapshot& end) {
  return {end.sent - begin.sent, end.recv - begin.recv};
}

struct PreparedBatchCircuitGmwState {
  size_t batch_idx = 0;
  size_t item_count = 0;
  size_t bit_width = 0;
  std::unique_ptr<coproto::AsioSocket> sock;
  volePSI::Gmw gmw;
  uint64_t setup_sent_bytes = 0;
  uint64_t setup_recv_bytes = 0;
};

struct PreparedCircuitGmwState {
  int rank = 0;
  size_t n = 0;
  size_t bit_width = 0;
  size_t input_count = 1;
  size_t batch_items = 0;
  std::vector<std::shared_ptr<PreparedBatchCircuitGmwState>> batches;
  uint64_t setup_sent_bytes = 0;
  uint64_t setup_recv_bytes = 0;
};

inline std::shared_ptr<PreparedBatchCircuitGmwState> PrepareBatchCircuitGmw(
    int rank, size_t n, size_t bit_width, const volePSI::BetaCircuit& cir,
    const std::string& tag_prefix, size_t batch_idx) {
  if (n == 0) {
    return nullptr;
  }
  YACL_ENFORCE(bit_width > 0 && bit_width <= 128,
               "bit_width must be in [1, 128], got={}", bit_width);
  const std::string address = MakePeqtBatchAddress(batch_idx);

  auto state = std::make_shared<PreparedBatchCircuitGmwState>();
  state->batch_idx = batch_idx;
  state->item_count = n;
  state->bit_width = bit_width;
  const size_t triple_ots = EstimateGmwTripleOtCount(n, cir);
  const size_t triple_batch = GmwTripleBatchSizeFor(n, cir);
  const size_t triple_batches =
      triple_ots == 0 ? 0 : CeilDivSize(triple_ots, triple_batch);

  {
    std::ostringstream oss;
    oss << "batch prepare start tag=" << tag_prefix << ", rank=" << rank
        << ", n=" << n << ", bit_width=" << bit_width
        << ", address=" << address
        << ", gmw_threads=" << GmwThreadCount()
        << ", triple_ots=" << triple_ots
        << ", triple_batch=" << triple_batch
        << ", triple_batches=" << triple_batches;
    PeqtDebugLog(oss.str());
  }

  state->sock =
      std::make_unique<coproto::AsioSocket>(ConnectPeqtSocket(address, rank == 1));
  auto local_cir = cir;
  state->gmw.init(n, local_cir, GmwThreadCount(), rank,
                  rank == 0 ? oc::ZeroBlock : oc::OneBlock);

  const auto bytes_begin = TakeSocketBytesSnapshot(*state->sock);
  PeqtDebugLog("batch generateTriple start tag=" + tag_prefix);
  coproto::sync_wait(
      state->gmw.generateTriple(triple_batch, GmwThreadCount(), *state->sock));
  PeqtDebugLog("batch generateTriple done tag=" + tag_prefix);
  FlushLocalSocket(*state->sock);
  const auto bytes_end = TakeSocketBytesSnapshot(*state->sock);
  const auto bytes_diff = DiffSocketBytes(bytes_begin, bytes_end);
  state->setup_sent_bytes = bytes_diff.sent;
  state->setup_recv_bytes = bytes_diff.recv;

  {
    std::ostringstream oss;
    oss << "batch prepare done tag=" << tag_prefix << ", rank=" << rank
        << ", n=" << n;
    PeqtDebugLog(oss.str());
  }
  return state;
}

inline void RunPreparedBatchCircuitGmw(
    int rank, PreparedBatchCircuitGmwState* state, const uint128_t* my_vec,
    const std::string& tag_prefix, uint8_t* out_share) {
  YACL_ENFORCE(state != nullptr, "prepared batch state must not be null");
  YACL_ENFORCE(state->sock != nullptr, "prepared batch socket must not be null");
  auto input = MakeInputMatrix(my_vec, state->item_count, state->bit_width);
  state->gmw.setInput(0, input);

  const auto bytes_begin = TakeSocketBytesSnapshot(*state->sock);
  PeqtDebugLog("batch run start tag=" + tag_prefix);
  coproto::sync_wait(state->gmw.run(*state->sock));
  PeqtDebugLog("batch run done tag=" + tag_prefix);
  FlushLocalSocket(*state->sock);
  const auto bytes_end = TakeSocketBytesSnapshot(*state->sock);
  const auto bytes_diff = DiffSocketBytes(bytes_begin, bytes_end);
  local_comm_stats::Record(rank, bytes_diff.sent, bytes_diff.recv);

  volePSI::Matrix<volePSI::u8> out;
  out.resize(state->item_count, 1);
  state->gmw.getOutput(0, out);
  for (size_t i = 0; i < state->item_count; ++i) {
    out_share[i] = static_cast<uint8_t>(out[i][0] & 1U);
  }

  {
    std::ostringstream oss;
    oss << "batch done tag=" << tag_prefix << ", rank=" << rank
        << ", n=" << state->item_count;
    PeqtDebugLog(oss.str());
  }
}

inline void RunPreparedMultiInputBatchCircuitGmw(
    int rank, PreparedBatchCircuitGmwState* state,
    const std::vector<const uint128_t*>& my_inputs,
    const std::string& tag_prefix, uint8_t* out_share) {
  YACL_ENFORCE(state != nullptr, "prepared batch state must not be null");
  YACL_ENFORCE(state->sock != nullptr, "prepared batch socket must not be null");
  YACL_ENFORCE(!my_inputs.empty(), "multi-input GMW expects at least one input");

  std::vector<volePSI::Matrix<volePSI::u8>> inputs;
  inputs.reserve(my_inputs.size());
  for (const auto* input_ptr : my_inputs) {
    YACL_ENFORCE(input_ptr != nullptr, "multi-input GMW got null input ptr");
    inputs.emplace_back(
        MakeInputMatrix(input_ptr, state->item_count, state->bit_width));
  }
  for (size_t i = 0; i < inputs.size(); ++i) {
    state->gmw.setInput(static_cast<volePSI::u64>(i), inputs[i]);
  }

  const auto bytes_begin = TakeSocketBytesSnapshot(*state->sock);
  PeqtDebugLog("multi batch run start tag=" + tag_prefix);
  coproto::sync_wait(state->gmw.run(*state->sock));
  PeqtDebugLog("multi batch run done tag=" + tag_prefix);
  FlushLocalSocket(*state->sock);
  const auto bytes_end = TakeSocketBytesSnapshot(*state->sock);
  const auto bytes_diff = DiffSocketBytes(bytes_begin, bytes_end);
  local_comm_stats::Record(rank, bytes_diff.sent, bytes_diff.recv);

  volePSI::Matrix<volePSI::u8> out;
  out.resize(state->item_count, 1);
  state->gmw.getOutput(0, out);
  for (size_t i = 0; i < state->item_count; ++i) {
    out_share[i] = static_cast<uint8_t>(out[i][0] & 1U);
  }

  {
    std::ostringstream oss;
    oss << "multi batch done tag=" << tag_prefix << ", rank=" << rank
        << ", n=" << state->item_count;
    PeqtDebugLog(oss.str());
  }
}

inline PreparedCircuitGmwState PrepareU128VecCircuit2PC(
    int rank, size_t n, size_t bit_width, const volePSI::BetaCircuit& cir,
    const std::string& tag_prefix) {
  PreparedCircuitGmwState state;
  state.rank = rank;
  state.n = n;
  state.bit_width = bit_width;
  state.input_count = 1;
  if (n == 0) {
    return state;
  }
  YACL_ENFORCE(bit_width > 0 && bit_width <= 128,
               "bit_width must be in [1, 128], got={}", bit_width);

  state.batch_items = std::max<size_t>(1, PeqtBatchItemCount());
  const size_t batch_count = (n + state.batch_items - 1) / state.batch_items;
  const size_t parallel_batches =
      std::min(batch_count, std::max<size_t>(1, PeqtParallelBatchCount()));

  state.batches.resize(batch_count);
  std::vector<std::future<void>> inflight(batch_count);
  size_t launched = 0;
  size_t completed = 0;
  while (completed < batch_count) {
    while (launched < batch_count &&
           (launched - completed) < parallel_batches) {
      const size_t batch_idx = launched++;
      const size_t offset = batch_idx * state.batch_items;
      const size_t batch_n = std::min(state.batch_items, n - offset);
      inflight[batch_idx] = std::async(std::launch::async, [&, batch_idx, batch_n]() {
        state.batches[batch_idx] = PrepareBatchCircuitGmw(
            rank, batch_n, bit_width, cir,
            tag_prefix + "_GMW_B" + std::to_string(batch_idx), batch_idx);
      });
    }
    inflight[completed++].get();
  }

  for (const auto& batch_state : state.batches) {
    if (!batch_state) {
      continue;
    }
    state.setup_sent_bytes += batch_state->setup_sent_bytes;
    state.setup_recv_bytes += batch_state->setup_recv_bytes;
  }
  return state;
}

inline std::vector<uint8_t> RunPreparedU128VecCircuit2PC(
    const PreparedCircuitGmwState& prepared, const std::vector<uint128_t>& my_vec,
    const std::string& tag_prefix) {
  YACL_ENFORCE(my_vec.size() == prepared.n,
               "prepared single-input GMW size mismatch: got {}, expect {}",
               my_vec.size(), prepared.n);
  if (prepared.n == 0) {
    return {};
  }

  const size_t batch_count = prepared.batches.size();
  const size_t parallel_batches =
      std::min(batch_count, std::max<size_t>(1, PeqtParallelBatchCount()));
  std::vector<uint8_t> out_share(prepared.n, 0);
  std::vector<std::future<void>> inflight(batch_count);
  size_t launched = 0;
  size_t completed = 0;
  while (completed < batch_count) {
    while (launched < batch_count &&
           (launched - completed) < parallel_batches) {
      const size_t batch_idx = launched++;
      const size_t offset = batch_idx * prepared.batch_items;
      const auto batch_state = prepared.batches[batch_idx];
      inflight[batch_idx] =
          std::async(std::launch::async,
                     [&, batch_idx, offset, batch_state]() {
                       RunPreparedBatchCircuitGmw(
                           prepared.rank, batch_state.get(),
                           my_vec.data() + offset,
                           tag_prefix + "_GMW_B" + std::to_string(batch_idx),
                           out_share.data() + offset);
                     });
    }
    inflight[completed++].get();
  }
  return out_share;
}

inline PreparedCircuitGmwState PrepareU128MultiVecCircuit2PC(
    int rank, size_t n, size_t bit_width, size_t input_count,
    const volePSI::BetaCircuit& cir, const std::string& tag_prefix) {
  YACL_ENFORCE(input_count > 0,
               "multi-input circuit expects at least one input bundle");
  auto state = PrepareU128VecCircuit2PC(rank, n, bit_width, cir, tag_prefix);
  state.input_count = input_count;
  return state;
}

inline std::vector<uint8_t> RunPreparedU128MultiVecCircuit2PC(
    const PreparedCircuitGmwState& prepared,
    const std::vector<std::vector<uint128_t>>& input_bundles,
    const std::string& tag_prefix) {
  YACL_ENFORCE(!input_bundles.empty(),
               "multi-input circuit expects at least one input bundle");
  YACL_ENFORCE(input_bundles.size() == prepared.input_count,
               "prepared multi-input GMW bundle-count mismatch: got {}, expect {}",
               input_bundles.size(), prepared.input_count);
  for (size_t i = 0; i < input_bundles.size(); ++i) {
    YACL_ENFORCE(input_bundles[i].size() == prepared.n,
                 "input bundle size mismatch at {}: got {}, expect {}", i,
                 input_bundles[i].size(), prepared.n);
  }
  if (prepared.n == 0) {
    return {};
  }

  const size_t batch_count = prepared.batches.size();
  const size_t parallel_batches =
      std::min(batch_count, std::max<size_t>(1, PeqtParallelBatchCount()));
  std::vector<uint8_t> out_share(prepared.n, 0);
  std::vector<std::future<void>> inflight(batch_count);
  size_t launched = 0;
  size_t completed = 0;
  while (completed < batch_count) {
    while (launched < batch_count &&
           (launched - completed) < parallel_batches) {
      const size_t batch_idx = launched++;
      const size_t offset = batch_idx * prepared.batch_items;
      const auto batch_state = prepared.batches[batch_idx];
      inflight[batch_idx] =
          std::async(std::launch::async,
                     [&, batch_idx, offset, batch_state]() {
                       std::vector<const uint128_t*> ptrs;
                       ptrs.reserve(input_bundles.size());
                       for (const auto& bundle : input_bundles) {
                         ptrs.push_back(bundle.data() + offset);
                       }
                       RunPreparedMultiInputBatchCircuitGmw(
                           prepared.rank, batch_state.get(), ptrs,
                           tag_prefix + "_GMW_B" + std::to_string(batch_idx),
                           out_share.data() + offset);
                     });
    }
    inflight[completed++].get();
  }
  return out_share;
}

inline void EqU128BatchGmw(int rank, const uint128_t* my_vec, size_t n,
                           size_t bit_width, const std::string& tag_prefix,
                           size_t batch_idx, uint8_t* eq_share_out) {
  auto cir = volePSI::isZeroCircuit(bit_width);
  auto prepared =
      PrepareBatchCircuitGmw(rank, n, bit_width, cir, tag_prefix, batch_idx);
  RunPreparedBatchCircuitGmw(rank, prepared.get(), my_vec, tag_prefix,
                             eq_share_out);
}

inline std::vector<uint8_t> U128VecCircuit2PC(
    int rank, const std::vector<uint128_t>& my_vec, size_t bit_width,
    const volePSI::BetaCircuit& cir, const std::string& tag_prefix) {
  auto prepared = PrepareU128VecCircuit2PC(rank, my_vec.size(), bit_width, cir,
                                           tag_prefix);
  return RunPreparedU128VecCircuit2PC(prepared, my_vec, tag_prefix);
}

inline std::vector<uint8_t> U128MultiVecCircuit2PC(
    int rank, const std::vector<std::vector<uint128_t>>& input_bundles,
    size_t bit_width, const volePSI::BetaCircuit& cir,
    const std::string& tag_prefix) {
  YACL_ENFORCE(!input_bundles.empty(),
               "multi-input circuit expects at least one input bundle");
  const uint64_t my_n = static_cast<uint64_t>(input_bundles.front().size());
  for (size_t i = 1; i < input_bundles.size(); ++i) {
    YACL_ENFORCE(input_bundles[i].size() == static_cast<size_t>(my_n),
                 "input bundle size mismatch at {}: got {}, expect {}", i,
                 input_bundles[i].size(), my_n);
  }
  auto prepared = PrepareU128MultiVecCircuit2PC(
      rank, static_cast<size_t>(my_n), bit_width, input_bundles.size(), cir,
      tag_prefix);
  return RunPreparedU128MultiVecCircuit2PC(prepared, input_bundles, tag_prefix);
}

inline PreparedCircuitGmwState PrepareEqU128Vec2PCPreRot(
    int rank, size_t n, size_t bit_width, const std::string& tag_prefix) {
  auto cir = volePSI::isZeroCircuit(bit_width);
  return PrepareU128VecCircuit2PC(rank, n, bit_width, cir, tag_prefix);
}

inline std::vector<uint8_t> RunPreparedEqU128Vec2PCPreRot(
    const PreparedCircuitGmwState& prepared,
    const std::vector<uint128_t>& my_vec, const std::string& tag_prefix) {
  return RunPreparedU128VecCircuit2PC(prepared, my_vec, tag_prefix);
}

inline PreparedCircuitGmwState PrepareAnyZeroU128Blocks2PC(
    int rank, size_t block_count, size_t rows_per_block, size_t bit_width,
    const std::string& tag_prefix) {
  YACL_ENFORCE(rows_per_block > 0,
               "rows_per_block must be positive, got={}", rows_per_block);
  auto cir = volePSI::anyZeroCircuit(static_cast<volePSI::u64>(rows_per_block),
                                     static_cast<volePSI::u64>(bit_width));
  return PrepareU128MultiVecCircuit2PC(rank, block_count, bit_width,
                                       rows_per_block, cir, tag_prefix);
}

inline std::vector<uint8_t> RunPreparedAnyZeroU128Blocks2PC(
    const PreparedCircuitGmwState& prepared, const std::vector<uint128_t>& my_vec,
    size_t rows_per_block, const std::string& tag_prefix) {
  if (my_vec.empty()) {
    return {};
  }
  YACL_ENFORCE(rows_per_block > 0,
               "rows_per_block must be positive, got={}", rows_per_block);
  YACL_ENFORCE(my_vec.size() % rows_per_block == 0,
               "input size {} is not divisible by rows_per_block {}",
               my_vec.size(), rows_per_block);
  const size_t block_count = my_vec.size() / rows_per_block;
  YACL_ENFORCE(block_count == prepared.n,
               "prepared any-zero block count mismatch: got {}, expect {}",
               block_count, prepared.n);
  YACL_ENFORCE(prepared.input_count == rows_per_block,
               "prepared any-zero rows_per_block mismatch: got {}, expect {}",
               rows_per_block, prepared.input_count);

  std::vector<std::vector<uint128_t>> bundles(
      rows_per_block, std::vector<uint128_t>(block_count, 0));
  for (size_t block_idx = 0; block_idx < block_count; ++block_idx) {
    for (size_t row_idx = 0; row_idx < rows_per_block; ++row_idx) {
      bundles[row_idx][block_idx] = my_vec[block_idx * rows_per_block + row_idx];
    }
  }
  return RunPreparedU128MultiVecCircuit2PC(prepared, bundles, tag_prefix);
}

inline std::vector<uint8_t> EqU128Vec2PCPreRot(
    int rank, const std::vector<uint128_t>& my_vec, size_t bit_width,
    const std::string& tag_prefix) {
  {
    std::ostringstream oss;
    oss << "party start tag=" << tag_prefix << ", rank=" << rank
        << ", n=" << my_vec.size() << ", bit_width=" << bit_width;
    PeqtDebugLog(oss.str());
  }
  auto prepared =
      PrepareEqU128Vec2PCPreRot(rank, my_vec.size(), bit_width, tag_prefix);
  auto eq_share = RunPreparedEqU128Vec2PCPreRot(prepared, my_vec, tag_prefix);
  PeqtDebugLog("party done tag=" + tag_prefix);
  return eq_share;
}

inline std::vector<uint8_t> AnyZeroU128Blocks2PC(
    int rank, const std::vector<uint128_t>& my_vec, size_t rows_per_block,
    size_t bit_width, const std::string& tag_prefix) {
  if (my_vec.empty()) {
    return {};
  }
  YACL_ENFORCE(rows_per_block > 0,
               "rows_per_block must be positive, got={}", rows_per_block);
  YACL_ENFORCE(my_vec.size() % rows_per_block == 0,
               "input size {} is not divisible by rows_per_block {}",
               my_vec.size(), rows_per_block);
  if (rows_per_block == 1) {
    return EqU128Vec2PCPreRot(rank, my_vec, bit_width, tag_prefix);
  }

  const size_t block_count = my_vec.size() / rows_per_block;

  {
    std::ostringstream oss;
    oss << "party start tag=" << tag_prefix << ", rank=" << rank
        << ", blocks=" << block_count << ", rows_per_block=" << rows_per_block
        << ", bit_width=" << bit_width;
    PeqtDebugLog(oss.str());
  }
  auto prepared = PrepareAnyZeroU128Blocks2PC(
      rank, block_count, rows_per_block, bit_width, tag_prefix);
  auto share = RunPreparedAnyZeroU128Blocks2PC(prepared, my_vec, rows_per_block,
                                               tag_prefix);
  PeqtDebugLog("party done tag=" + tag_prefix);
  return share;
}

inline std::vector<uint8_t> OrBitShareBlocks2PC(
    int rank, const std::vector<uint8_t>& input_bits, size_t block_size,
    const std::string& tag_prefix) {
  if (input_bits.empty()) {
    return {};
  }
  YACL_ENFORCE(block_size > 0 && block_size <= 128,
               "block_size must be in [1, 128], got={}", block_size);
  YACL_ENFORCE(input_bits.size() % block_size == 0,
               "input_bits size {} is not divisible by block_size {}",
               input_bits.size(), block_size);
  if (block_size == 1) {
    return input_bits;
  }

  const size_t block_count = input_bits.size() / block_size;
  std::vector<uint128_t> packed(block_count, 0);
  for (size_t block_idx = 0; block_idx < block_count; ++block_idx) {
    uint128_t value = 0;
    for (size_t bit_idx = 0; bit_idx < block_size; ++bit_idx) {
      value |= (uint128_t(input_bits[block_idx * block_size + bit_idx] & 1U)
                << bit_idx);
    }
    packed[block_idx] = value;
  }

  auto cir = volePSI::orCircuit(static_cast<volePSI::u64>(block_size));
  return U128VecCircuit2PC(rank, packed, block_size, cir, tag_prefix);
}

inline std::vector<uint8_t> Party(int rank,
                                  const std::vector<uint128_t>& a_vec,
                                  size_t bit_width) {
  return EqU128Vec2PCPreRot(rank, a_vec, bit_width, "PSU_PEQT");
}

}
