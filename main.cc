#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <iostream>
#include <utility>
#include <vector>

#include "examples/linerpsu/bench_items.h"
#include "examples/linerpsu/benchmark_stats.h"
#include "examples/linerpsu/cuckoohash.h"
#include "examples/linerpsu/eqote.h"
#include "examples/linerpsu/okvs/baxos.h"
#include "examples/linerpsu/permuted_peqt.h"
#include "examples/linerpsu/ps.h"
#include "examples/linerpsu/psu.h"
#include "examples/linerpsu/psu_bench_config.h"
#include "examples/linerpsu/socket_io.h"
#include "examples/linerpsu/stage_timing.h"
#include "examples/linerpsu/utils.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"

using namespace std;
using namespace std::chrono;

namespace {

linerpsu::bench::TrafficStats SocketTrafficDiff(
    const linerpsu::bench::TrafficStats& begin, coproto::Socket& sender_sock,
    coproto::Socket& receiver_sock) {
  linerpsu::socket_io::Flush(sender_sock);
  linerpsu::socket_io::Flush(receiver_sock);
  return linerpsu::bench::DiffTraffic(
      begin, linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock));
}

void PrintResultLine(uint64_t logn, uint64_t ns, uint64_t nr, uint64_t diff,
                     uint32_t cuckoolen, double offline_seconds,
                     double online_seconds,
                     const linerpsu::bench::TrafficStats& offline_comm,
                     const linerpsu::bench::TrafficStats& online_comm,
                     size_t result_size) {
  const auto total_comm =
      linerpsu::bench::AddTraffic(offline_comm, online_comm);
  std::cout << "LINERPSU_RESULT"
            << ",logn=" << logn
            << ",ns=" << ns
            << ",nr=" << nr
            << ",diff=" << diff
            << ",cuckoolen=" << cuckoolen
            << ",offline_s=" << offline_seconds
            << ",online_s=" << online_seconds
            << ",total_s=" << (offline_seconds + online_seconds)
            << ",offline_comm_bytes="
            << linerpsu::bench::TotalSentBytes(offline_comm)
            << ",online_comm_bytes="
            << linerpsu::bench::TotalSentBytes(online_comm)
            << ",total_comm_bytes="
            << linerpsu::bench::TotalSentBytes(total_comm)
            << ",result_size=" << result_size << std::endl;
}

void RunOurPSU() {
  auto opts = linerpsu::bench_config::LoadPsuOptions();
  const uint64_t ns = opts.ns;
  const uint64_t nr = opts.nr;
  const uint64_t diff = opts.diff;

  auto item_sets = linerpsu::bench_items::CreateBenchmarkItemSets(ns, nr, diff);
  cout << "ns: " << ns << ", nr: " << nr << ", diff: " << diff << endl;
  cout << "intersection size: " << item_sets.intersection_size << endl;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  cout << "cuckoo hash table size: " << cuckoolen << endl;

  CuckooHash T_X(ns);
  size_t bin_size = cuckoolen / 4;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  okvs::Baxos baxos2;
  double offline_seconds = 0.0;
  double online_seconds = 0.0;
  linerpsu::bench::TrafficStats offline_comm;
  linerpsu::bench::TrafficStats online_comm;

  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  baxos.Init(cuckoolen, bin_size, weight, ssp,
             okvs::PaxosParam::DenseType::GF128, seed);
  baxos2.Init(nr * 3, bin_size * 3, weight, ssp,
              okvs::PaxosParam::DenseType::GF128, seed);

  std::vector<uint128_t> items_a = std::move(item_sets.sender);
  std::vector<uint128_t> items_b = std::move(item_sets.receiver);

  auto sockets =
      linerpsu::socket_io::ConnectSocketPair(linerpsu::socket_io::PsuBaseAddress());
  coproto::Socket& sender_sock = sockets.first;
  coproto::Socket& receiver_sock = sockets.second;

  auto comm_begin =
      linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock);
  auto start_time = high_resolution_clock::now();
  std::future<std::vector<__uint128_t>> sender =
      std::async(std::launch::async, [&] {
        return psu::PSUSend(sender_sock, std::move(items_a), T_X, cuckoolen,
                            baxos, baxos2);
      });
  std::future<std::vector<__uint128_t>> receiver =
      std::async(std::launch::async, [&] {
        return psu::PSURecv(receiver_sock, items_b, cuckoolen, baxos, baxos2);
      });
  auto rs = sender.get();
  auto rr = receiver.get();
  auto end_time = high_resolution_clock::now();
  std::chrono::duration<double> duration0 = end_time - start_time;
  online_seconds += duration0.count();
  online_comm = linerpsu::bench::AddTraffic(
      online_comm, SocketTrafficDiff(comm_begin, sender_sock, receiver_sock));
  linerpsu::stage_timing::Print("psu masks", duration0.count());

  auto start_time1 = high_resolution_clock::now();
  uint128_t k = yacl::crypto::FastRandU128();
  auto pi = GenShuffledRangeWithYacl(cuckoolen);
  auto end_time1 = high_resolution_clock::now();
  std::chrono::duration<double> duration1 = end_time1 - start_time1;
  offline_seconds += duration1.count();
  linerpsu::stage_timing::Print("permutation", duration1.count());

  std::vector<uint128_t> fxs;
  std::vector<uint128_t> fxr;
  comm_begin = linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock);
  auto start_time2 = high_resolution_clock::now();
  RealSsoprf_AltMod_BenchStyleWithSockets(sender_sock, receiver_sock, pi, k,
                                          fxs, fxr);
  auto end_ssoprf_time = high_resolution_clock::now();
  const double ssoprf_seconds =
      std::chrono::duration<double>(end_ssoprf_time - start_time2).count();
  offline_seconds += ssoprf_seconds;
  offline_comm = linerpsu::bench::AddTraffic(
      offline_comm, SocketTrafficDiff(comm_begin, sender_sock, receiver_sock));
  linerpsu::stage_timing::Print("ssoprf", ssoprf_seconds);

  comm_begin = linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock);
  auto start_ps_time = high_resolution_clock::now();
  std::future<std::vector<__uint128_t>> pssender = std::async(
      std::launch::async, [&] { return ps::PSSend(sender_sock, pi, fxs); });
  std::future<std::vector<__uint128_t>> psreceiver =
      std::async(std::launch::async,
                 [&] { return ps::PSRecv(receiver_sock, fxr, rr, k); });
  auto rr1 = pssender.get();
  auto rr2 = psreceiver.get();
  auto end_time2 = high_resolution_clock::now();
  std::chrono::duration<double> duration2 = end_time2 - start_ps_time;
  online_seconds += duration2.count();
  online_comm = linerpsu::bench::AddTraffic(
      online_comm, SocketTrafficDiff(comm_begin, sender_sock, receiver_sock));
  linerpsu::stage_timing::Print("ps", duration2.count());

  auto peqt_shares = linerpsu::RunUpsuGmwPermutedPeqt(rr2, rr1, rs, pi);
  offline_seconds += peqt_shares.offline_seconds;
  online_seconds += peqt_shares.online_seconds;
  offline_comm = linerpsu::bench::AddTraffic(
      offline_comm, linerpsu::bench::FromPeqtComm(peqt_shares.offline_comm));
  online_comm = linerpsu::bench::AddTraffic(
      online_comm, linerpsu::bench::FromPeqtComm(peqt_shares.online_comm));
  linerpsu::stage_timing::Print("peqt offline",
                                peqt_shares.offline_seconds);
  linerpsu::stage_timing::Print("peqt online", peqt_shares.online_seconds);
  auto eqs = std::move(peqt_shares.sender);
  auto eqr = std::move(peqt_shares.receiver);

  comm_begin = linerpsu::bench::TakeSocketSnapshot(sender_sock, receiver_sock);
  auto start_time3 = high_resolution_clock::now();
  auto shufflecuckoo = ShuffleWithYacl(T_X, pi);
  std::future<void> eqotesender = std::async(std::launch::async, [&] {
    eqote::EQOTESend(sender_sock, eqs, shufflecuckoo);
  });
  std::future<std::vector<__uint128_t>> eqotereceiver = std::async(
      std::launch::async, [&] { return eqote::EQOTERecv(receiver_sock, eqr); });
  eqotesender.get();
  auto psuresults = eqotereceiver.get();
  auto end_time3 = high_resolution_clock::now();
  std::chrono::duration<double> duration3 = end_time3 - start_time3;
  online_seconds += duration3.count();
  online_comm = linerpsu::bench::AddTraffic(
      online_comm, SocketTrafficDiff(comm_begin, sender_sock, receiver_sock));
  linerpsu::stage_timing::Print("eqote", duration3.count());

  std::cout << "Offline time: " << offline_seconds << " seconds"
            << std::endl;
  std::cout << "Online time: " << online_seconds << " seconds" << std::endl;
  std::cout << "Total execution time (offline + online): "
            << (offline_seconds + online_seconds) << " seconds"
            << std::endl;
  items_b.insert(items_b.end(), psuresults.begin(), psuresults.end());
  std::cout << "Number of PSU results: " << items_b.size() << std::endl;

  if (opts.print_comm) {
    auto total_comm = linerpsu::bench::AddTraffic(offline_comm, online_comm);
    linerpsu::bench::PrintTraffic("Offline", offline_comm);
    linerpsu::bench::PrintTraffic("Online", online_comm);
    linerpsu::bench::PrintTraffic("Total", total_comm);
  }
  if (opts.result_line) {
    PrintResultLine(opts.logn, ns, nr, diff, cuckoolen, offline_seconds,
                    online_seconds, offline_comm, online_comm, items_b.size());
  }
}

}  // namespace

int main() {
  RunOurPSU();
  return 0;
}
