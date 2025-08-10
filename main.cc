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
#include "examples/linerpsu/oprf.h"
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

void RunEQOTE(){
    size_t num_ot = 1 << 16;  // 1M OTs
  const int kWorldSize = 2;
  auto lctxs = yacl::link::test::SetupWorld(kWorldSize);
  std::vector<uint128_t> m0s = yacl::crypto::RandVec<uint128_t>(num_ot);
  std::vector<uint128_t> m1s = yacl::crypto::RandVec<uint128_t>(num_ot);
  std::vector<bool> chooses1(num_ot);
  std::vector<bool> chooses2(num_ot);
  for (size_t i = 0; i < num_ot; ++i) {
    chooses1[i] = 1;
    chooses2[i] = 0;
  }
  std::vector<uint128_t> outputs;

  auto start_time = std::chrono::high_resolution_clock::now();
  auto recv_future = std::async(
      std::launch::async, [&] { outputs = eqote::EQOTERecv(lctxs[0], chooses1); });

  auto send_future =
      std::async(std::launch::async, [&] { eqote::EQOTESend(lctxs[1],chooses2,m0s); });

  recv_future.get();
  send_future.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Send and Receive operations took " << duration.count()
            << " seconds." << std::endl;
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

void RunOurPS(){
  std::vector<uint128_t> fxs;
  std::vector<uint128_t> fxr;
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  const uint64_t ns = 1 << 22;
  const uint64_t nr = 1 << 22;
  uint128_t k = yacl::crypto::FastRandU128();
  const uint64_t diff = 10;
  cout << "ns: " << ns << ", nr: " << nr << ", diff: " << diff << endl;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  auto rr = yacl::crypto::RandVec<uint128_t>(cuckoolen);
  auto pi = GenShuffledRangeWithYacl(cuckoolen);
  Fakessoprf(pi, k, fxs, fxr);
  auto start_time2 = std::chrono::high_resolution_clock::now();
  std::future<std::vector<__uint128_t>> pssender = std::async(
      std::launch::async, [&] { return ps::PSSend(lctxs[0], pi, fxs); });

  std::future<std::vector<__uint128_t>> psreceiver = std::async(
      std::launch::async, [&] { return ps::PSRecv(lctxs[1], fxr, rr, k); });
  auto rr1 = pssender.get();
  auto rr2 = psreceiver.get();
  auto end_time2 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration2 = end_time2 - start_time2;
  std::cout << "Execution time 2: " << duration2.count() << " seconds"<< std::endl;
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

void RunOurOprf(){
    size_t logn = 24;
  uint64_t num = 1 << logn;
  size_t bin_size = num / 4;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;
  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", num, bin_size);

  baxos.Init(num, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, num);
  std::vector<uint128_t> items_b = CreateRangeItems(0, num);


  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<void> sender = std::async(std::launch::async, [&] {
    oprf::OPRFSend(lctxs[0], items_a, baxos);
  });

  std::future<std::vector<uint128_t>> receiver = std::async(std::launch::async, [&] {
    return oprf::OPRFRecv(lctxs[1], items_b, baxos);
  });

  sender.get();
  auto psi_result = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  size_t count = std::count(psi_result.begin(), psi_result.end(), true);
  std::cout << count << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;

  std::sort(psi_result.begin(), psi_result.end());
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

void RunOurOpprf() {
  const uint64_t ns = 1 << 18;
  const uint64_t nr = 1 << 18;
  const uint64_t diff = 10;
  cout << "ns: " << ns << ", nr: " << nr << ", diff: " << diff << endl;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  cout << "cuckoo hash table size: " << cuckoolen << endl;
  CuckooHash T_X(ns);
  size_t bin_size = cuckoolen / 4;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  okvs::Baxos baxos2;
  //std::chrono::duration<double> total_duration(0);
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
  cout<< "Execution time 0: " << duration.count() << " seconds" << endl;
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

void RunOurPSU() {
  const uint64_t ns = 1 << 20;
  const uint64_t nr = 1 << 20;
  const uint64_t diff = 10;
  std::vector<uint128_t> common = CreateRangeItems(0, ns - diff);
  std::vector<uint128_t> unique_a = CreateRangeItems(ns - diff, diff);        
  std::vector<uint128_t> unique_b = CreateRangeItems(ns, diff);    
  cout << "ns: " << ns << ", nr: " << nr << ", diff: " << diff << endl;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  cout << "cuckoo hash table size: " << cuckoolen << endl;
  CuckooHash T_X(ns);
  size_t bin_size = cuckoolen / 4;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  okvs::Baxos baxos2;
  std::chrono::duration<double> total_duration(0);
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", cuckoolen, bin_size);

  baxos.Init(cuckoolen, bin_size, weight, ssp,
             okvs::PaxosParam::DenseType::GF128, seed);

  baxos2.Init(nr * 3, bin_size * 3, weight, ssp,
              okvs::PaxosParam::DenseType::GF128, seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());
  std::vector<uint128_t> items_a = common;
  items_a.insert(items_a.end(), unique_a.begin(), unique_a.end());
  std::vector<uint128_t> items_b = common;
  items_b.insert(items_b.end(), unique_b.begin(), unique_b.end());
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
  //cout<< "Execution time 0: " << duration.count() << " seconds" << endl;
  total_duration = total_duration + duration;

  auto start_time1 = std::chrono::high_resolution_clock::now();
  uint128_t k = yacl::crypto::FastRandU128();
  auto pi = GenShuffledRangeWithYacl(cuckoolen);
  auto end_time1 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration1 = end_time1 - start_time1;
  //std::cout << "Execution time 1: " << duration1.count() << " seconds"<< std::endl;
  total_duration = total_duration + duration1;

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
  std::chrono::duration<double> duration2 = end_time2 - start_time2;
  //std::cout << "Execution time 2: " << duration2.count() << " seconds"<< std::endl;
  total_duration = total_duration + duration2;
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

  std::chrono::duration<double> duration3 = end_time3 - start_time3;
  //std::cout << "Execution time 3: " << duration3.count() << " seconds"<< std::endl;
  total_duration = total_duration + duration3;
  std::cout << "Total execution time: " << total_duration.count()
            << " seconds" << std::endl;
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

void RunOurPSUwithBPSY() {
  const uint64_t ns = 1 << 8;
  const uint64_t nr = 1 << 8;
  const uint64_t diff = 10;
  cout << "ns: " << ns << ", nr: " << nr << ", diff: " << diff << endl;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  cout << "cuckoo hash table size: " << cuckoolen << endl;
  CuckooHash T_X(ns);
  size_t w = 120;
  double e = 1.03;
  OKVSBK baxos(cuckoolen, w, e);
  OKVSBK baxos2(nr * 3, w * 3, e);
  std::chrono::duration<double> total_duration(0);
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
  //cout<< "Execution time 0: " << duration.count() << " seconds" << endl;
  total_duration = total_duration + duration;

  auto start_time1 = std::chrono::high_resolution_clock::now();
  uint128_t k = yacl::crypto::FastRandU128();
  auto pi = GenShuffledRangeWithYacl(cuckoolen);
  auto end_time1 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration1 = end_time1 - start_time1;
  //std::cout << "Execution time 1: " << duration1.count() << " seconds"<< std::endl;
  total_duration = total_duration + duration1;

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
  std::chrono::duration<double> duration2 = end_time2 - start_time2;
  //std::cout << "Execution time 2: " << duration2.count() << " seconds"<< std::endl;
  total_duration = total_duration + duration2;
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

  std::chrono::duration<double> duration3 = end_time3 - start_time3;
  //std::cout << "Execution time 3: " << duration3.count() << " seconds"<< std::endl;
  total_duration = total_duration + duration3;
  std::cout << "Total execution time: " << total_duration.count()
            << " seconds" << std::endl;
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


void RunOurOpprfwithBPSY() {
  const uint64_t ns = 1 << 22;
  const uint64_t nr = 1 << 22;
  const uint64_t diff = 10;
  cout << "ns: " << ns << ", nr: " << nr << ", diff: " << diff << endl;
  uint32_t cuckoolen = static_cast<uint32_t>(ns * 1.27);
  cout << "cuckoo hash table size: " << cuckoolen << endl;
  CuckooHash T_X(ns);
  size_t w = 240;
  double e = 1.03;
  OKVSBK baxos(cuckoolen, w, e);
  OKVSBK baxos2(nr * 3, w * 3, e);
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
  cout<< "Execution time 0: " << duration.count() << " seconds" << endl;

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
  RunOurPSU();
  //RunOurOprf();
  //RunOurPSUwithBPSY();
  //RunEQOTE();
  //RunOurPS();
  //RunOurOpprf();
  //RunOurOpprfwithBPSY();
  return 0;
}
