#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "coproto/coproto.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "examples/linerpsu/benchmark_stats.h"
#include "examples/linerpsu/coproto_asio_globals.h"
#include "examples/linerpsu/own_opprf.h"
#include "examples/linerpsu/rr22_oprf.h"
#include "examples/linerpsu/socket_io.h"
#include "yacl/base/exception.h"

namespace {

using Clock = std::chrono::high_resolution_clock;
using OwnOpprfReceiver = linerpsu::own_opprf::Receiver;
using OwnOpprfSender = linerpsu::own_opprf::Sender;
using Rr22OprfReceiver = linerpsu::rr22_oprf::Receiver;
using Rr22OprfSender = linerpsu::rr22_oprf::Sender;

struct BenchResult {
  int logn = 0;
  uint64_t n = 0;
  double seconds = 0.0;
  uint64_t comm_bytes = 0;
  bool ok = false;
};

struct Options {
  std::vector<int> logns = {18, 20, 22, 24};
  std::string csv_path =
      "/home/lgw/yacl/examples/linerpsu/results/Ours/"
      "mask_generation_opprf_compare.csv";
  uint64_t threads = 1;
  bool run_rr22 = true;
  bool run_own = true;
};

uint64_t EnvU64(const char* name, uint64_t fallback) {
  const char* value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return fallback;
  }
  return std::stoull(value);
}

Options ParseArgs(int argc, char** argv) {
  Options opts;
  opts.threads = EnvU64("LINERPSU_OPPRF_THREADS", 1);
  opts.logns.clear();

  for (int i = 1; i < argc; ++i) {
    std::string arg(argv[i]);
    constexpr std::string_view csv_prefix = "--csv=";
    constexpr std::string_view variant_prefix = "--variant=";
    constexpr std::string_view threads_prefix = "--threads=";
    if (arg.rfind(csv_prefix, 0) == 0) {
      opts.csv_path = arg.substr(csv_prefix.size());
    } else if (arg.rfind(variant_prefix, 0) == 0) {
      const auto variant = arg.substr(variant_prefix.size());
      if (variant == "own") {
        opts.run_rr22 = false;
        opts.run_own = true;
      } else if (variant == "rr22") {
        opts.run_rr22 = true;
        opts.run_own = false;
      } else if (variant == "both") {
        opts.run_rr22 = true;
        opts.run_own = true;
      } else if (variant == "volepsi") {
        throw std::invalid_argument(
            "VOLE-PSI OPPRF was removed from this benchmark output");
      } else {
        throw std::invalid_argument("unknown --variant=" + variant);
      }
    } else if (arg.rfind(threads_prefix, 0) == 0) {
      opts.threads = std::stoull(arg.substr(threads_prefix.size()));
    } else {
      opts.logns.push_back(std::stoi(arg));
    }
  }

  if (opts.logns.empty()) {
    opts.logns = {18, 20, 22, 24};
  }
  YACL_ENFORCE(opts.threads >= 1, "threads must be >= 1");
  YACL_ENFORCE(opts.run_rr22 || opts.run_own, "no benchmark variant selected");
  return opts;
}

std::vector<oc::block> MakeRandomBlocks(uint64_t n, oc::PRNG& prng) {
  std::vector<oc::block> out(n);
  prng.get(out.data(), out.size());
  return out;
}

bool EqualBlocks(const std::vector<oc::block>& a,
                 const std::vector<oc::block>& b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (uint64_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

BenchResult RunOwnOne(int logn, uint64_t threads, size_t address_offset) {
  const uint64_t n = uint64_t{1} << logn;
  oc::PRNG data_prng(oc::block(0xC0FFEE, static_cast<uint64_t>(logn)));
  std::vector<oc::block> keys = MakeRandomBlocks(n, data_prng);
  std::vector<oc::block> receiver_keys = keys;
  std::vector<oc::block> sender_masks(n);
  std::vector<oc::block> receiver_masks(n);

  const std::string address = linerpsu::socket_io::OffsetAddress(
      linerpsu::socket_io::PsuBaseAddress(), address_offset);
  auto sockets = linerpsu::socket_io::ConnectSocketPair(address);
  coproto::Socket& sender_sock = sockets.first;
  coproto::Socket& receiver_sock = sockets.second;

  OwnOpprfSender sender;
  OwnOpprfReceiver receiver;
  oc::PRNG sender_prng(oc::block(2, static_cast<uint64_t>(logn)));
  oc::PRNG receiver_prng(oc::block(3, static_cast<uint64_t>(logn)));

  auto comm_begin =
      linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock);
  const auto begin = Clock::now();

  auto sender_task = std::async(std::launch::async, [&] {
    coproto::sync_wait(sender.GenerateMasks(
        oc::span<const oc::block>(keys.data(), keys.size()),
        oc::span<oc::block>(sender_masks.data(), sender_masks.size()),
        sender_prng, sender_sock, threads));
    linerpsu::socket_io::Flush(sender_sock);
  });

  auto receiver_task = std::async(std::launch::async, [&] {
    coproto::sync_wait(receiver.GenerateMasks(
        oc::span<const oc::block>(receiver_keys.data(), receiver_keys.size()),
        oc::span<oc::block>(receiver_masks.data(), receiver_masks.size()),
        receiver_prng, receiver_sock, threads));
    linerpsu::socket_io::Flush(receiver_sock);
  });

  sender_task.get();
  receiver_task.get();

  const auto end = Clock::now();
  const auto comm = linerpsu::bench::DiffTraffic(
      comm_begin,
      linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock));

  BenchResult result;
  result.logn = logn;
  result.n = n;
  result.seconds = std::chrono::duration<double>(end - begin).count();
  result.comm_bytes = linerpsu::bench::TotalSentBytes(comm);
  result.ok = EqualBlocks(sender_masks, receiver_masks);

  std::cout << "OPPRF_MASK_RESULT"
            << ",variant=own"
            << ",logn=" << result.logn
            << ",n=" << result.n
            << ",time_s=" << std::fixed << std::setprecision(6)
            << result.seconds
            << ",comm_bytes=" << result.comm_bytes
            << ",comm_mb=" << linerpsu::bench::BytesToMB(result.comm_bytes)
            << ",ok=" << (result.ok ? 1 : 0) << std::endl;
  return result;
}

BenchResult RunRr22One(int logn, uint64_t threads, size_t address_offset) {
  const uint64_t n = uint64_t{1} << logn;
  oc::PRNG data_prng(oc::block(0xC0FFEE, static_cast<uint64_t>(logn)));
  std::vector<oc::block> keys = MakeRandomBlocks(n, data_prng);
  std::vector<oc::block> receiver_keys = keys;
  std::vector<oc::block> sender_masks(n);
  std::vector<oc::block> receiver_masks(n);

  const std::string address = linerpsu::socket_io::OffsetAddress(
      linerpsu::socket_io::PsuBaseAddress(), address_offset);
  auto sockets = linerpsu::socket_io::ConnectSocketPair(address);
  coproto::Socket& sender_sock = sockets.first;
  coproto::Socket& receiver_sock = sockets.second;

  Rr22OprfSender sender;
  Rr22OprfReceiver receiver;
  oc::PRNG sender_prng(oc::block(4, static_cast<uint64_t>(logn)));
  oc::PRNG receiver_prng(oc::block(5, static_cast<uint64_t>(logn)));

  auto comm_begin =
      linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock);
  const auto begin = Clock::now();

  auto sender_task = std::async(std::launch::async, [&] {
    coproto::sync_wait(sender.GenerateMasks(
        oc::span<const oc::block>(keys.data(), keys.size()),
        oc::span<oc::block>(sender_masks.data(), sender_masks.size()),
        sender_prng, sender_sock, threads));
    linerpsu::socket_io::Flush(sender_sock);
  });

  auto receiver_task = std::async(std::launch::async, [&] {
    coproto::sync_wait(receiver.GenerateMasks(
        oc::span<const oc::block>(receiver_keys.data(), receiver_keys.size()),
        oc::span<oc::block>(receiver_masks.data(), receiver_masks.size()),
        receiver_prng, receiver_sock, threads));
    linerpsu::socket_io::Flush(receiver_sock);
  });

  sender_task.get();
  receiver_task.get();

  const auto end = Clock::now();
  const auto comm = linerpsu::bench::DiffTraffic(
      comm_begin,
      linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock));

  BenchResult result;
  result.logn = logn;
  result.n = n;
  result.seconds = std::chrono::duration<double>(end - begin).count();
  result.comm_bytes = linerpsu::bench::TotalSentBytes(comm);
  result.ok = EqualBlocks(sender_masks, receiver_masks);

  std::cout << "OPRF_MASK_RESULT"
            << ",variant=rr22"
            << ",logn=" << result.logn
            << ",n=" << result.n
            << ",time_s=" << std::fixed << std::setprecision(6)
            << result.seconds
            << ",comm_bytes=" << result.comm_bytes
            << ",comm_mb=" << linerpsu::bench::BytesToMB(result.comm_bytes)
            << ",ok=" << (result.ok ? 1 : 0) << std::endl;
  return result;
}

std::string Number(double value, int precision = 6) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(precision) << value;
  return oss.str();
}

void WriteMetricRows(std::ofstream& out, std::string_view scheme,
                     const std::vector<BenchResult>& rows) {
  if (rows.empty()) {
    return;
  }
  out << scheme << ",Time (s)";
  for (const auto& row : rows) {
    out << "," << Number(row.seconds);
  }
  out << "\n";

  out << scheme << ",Communication (MB)";
  for (const auto& row : rows) {
    out << "," << Number(linerpsu::bench::BytesToMB(row.comm_bytes));
  }
  out << "\n";
}

void WriteCsv(const std::string& path, const std::vector<int>& logns,
              const std::vector<BenchResult>& rr22_rows,
              const std::vector<BenchResult>& own_rows) {
  const std::filesystem::path out_path(path);
  if (out_path.has_parent_path()) {
    std::filesystem::create_directories(out_path.parent_path());
  }

  std::ofstream out(path);
  if (!out) {
    throw std::runtime_error("failed to open csv: " + path);
  }

  out << "scheme,metric";
  for (const int logn : logns) {
    out << ",2^" << logn;
  }
  out << "\n";

  WriteMetricRows(out, "RR22", rr22_rows);
  WriteMetricRows(out, "Ours", own_rows);
}

}  // namespace

int main(int argc, char** argv) {
  const Options opts = ParseArgs(argc, argv);

  std::vector<BenchResult> rr22_rows;
  std::vector<BenchResult> own_rows;
  rr22_rows.reserve(opts.logns.size());
  own_rows.reserve(opts.logns.size());

  size_t address_offset = 0;
  for (const int logn : opts.logns) {
    if (opts.run_rr22) {
      rr22_rows.push_back(RunRr22One(logn, opts.threads, address_offset++));
      YACL_ENFORCE(rr22_rows.back().ok,
                   "RR22 OPRF correctness check failed at logn={}", logn);
    }
    if (opts.run_own) {
      own_rows.push_back(RunOwnOne(logn, opts.threads, address_offset++));
      YACL_ENFORCE(own_rows.back().ok,
                   "own OPPRF correctness check failed at logn={}", logn);
    }
  }

  WriteCsv(opts.csv_path, opts.logns, rr22_rows, own_rows);
  std::cout << "OPPRF_MASK_CSV " << opts.csv_path << std::endl;
  return 0;
}
