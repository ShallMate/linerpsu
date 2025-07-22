#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "examples/linerpsu/cuckoohash.h"
#include "examples/linerpsu/eqote.h"
#include "examples/linerpsu/okvs/baxos.h"
#include "examples/linerpsu/ps.h"
#include "examples/linerpsu/psu.h"
#include "examples/linerpsu/utils.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

void OurPSURR22() {
  const uint64_t ns = 1 << 16;
  const uint64_t nr = 1 << 16;
  const uint64_t diff = 10;
  cout << "ns: " << ns << ", nr: " << nr << ", diff: " << diff << endl;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  cout << "cuckoolen: " << cuckoolen << endl;
  CuckooHash T_X(ns);
  size_t bin_size = cuckoolen / 4;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  okvs::Baxos baxos2;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", cuckoolen, bin_size);

  baxos.Init(cuckoolen, bin_size, weight, ssp,
             okvs::PaxosParam::DenseType::GF128, seed);

  baxos2.Init(nr * 3, bin_size * 3, weight, ssp,
              okvs::PaxosParam::DenseType::GF128, seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());
  std::vector<uint128_t> items_a = CreateRangeItems(0, ns);
  std::vector<uint128_t> items_b = CreateRangeItems(diff, nr);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  lctxs[0]->SetRecvTimeout(120000);
  lctxs[1]->SetRecvTimeout(120000);
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<std::vector<__uint128_t>> sender =
      std::async(std::launch::async, [&] {
        return psu::PSUSend(lctxs[0], items_a, T_X, cuckoolen, baxos, baxos2);
      });

  std::future<std::vector<__uint128_t>> receiver =
      std::async(std::launch::async, [&] {
        return psu::PSURecv(lctxs[1], items_b, cuckoolen, baxos, baxos2);
      });
  auto rs = sender.get();
  auto rr = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;

  auto start_time1 = std::chrono::high_resolution_clock::now();
  uint128_t k = yacl::crypto::FastRandU128();
  auto pi = GenShuffledRangeWithYacl(cuckoolen);
  auto end_time1 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration1 = end_time1 - start_time1 + duration;
  std::vector<uint128_t> fxs;
  std::vector<uint128_t> fxr;
  Fakessoprf(pi, k, fxs, fxr);
  auto start_time2 = std::chrono::high_resolution_clock::now();
  std::future<std::vector<__uint128_t>> pssender = std::async(
      std::launch::async, [&] { return ps::PSSend(lctxs[0], pi, fxs); });

  std::future<std::vector<__uint128_t>> psreceiver = std::async(
      std::launch::async, [&] { return ps::PSRecv(lctxs[1], fxr, rr, k); });
  auto rr1 = pssender.get();
  auto rr2 = psreceiver.get();
  auto end_time2 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration2 = end_time2 - start_time2 + duration1;
  std::vector<bool> eqs;
  std::vector<bool> eqr;
  FakePiPEQT(rr1, rr2, rs, pi, eqs, eqr);
  auto start_time3 = std::chrono::high_resolution_clock::now();
  auto shufflecuckoo = ShuffleWithYacl(T_X, pi);
  std::future<void> eqotesender = std::async(std::launch::async, [&] {
    eqote::EQOTESend(lctxs[0], eqs, shufflecuckoo);
  });
  std::future<std::vector<__uint128_t>> eqotereceiver = std::async(
      std::launch::async, [&] { return eqote::EQOTERecv(lctxs[1], eqr); });
  eqotesender.get();
  auto psuresults = eqotereceiver.get();
  auto end_time3 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration3 = end_time3 - start_time3 + duration2;
  std::cout << "Execution time: " << duration3.count() << " seconds"
            << std::endl;
  items_b.insert(items_b.end(), psuresults.begin(), psuresults.end());
  std::cout << "Number of PSU results: " << items_b.size() << std::endl;
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

int main() {
  OurPSURR22();
  return 0;
}
