#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_split.h"
#include "fmt/format.h"
#include "libspu/core/config.h"
#include "libspu/device/io.h"
#include "libspu/kernel/hal/public_helper.h"
#include "libspu/kernel/hlo/basic_binary.h"
#include "libspu/kernel/hlo/casting.h"
#include "libspu/mpc/factory.h"
#include "libspu/spu.pb.h"
#include "xtensor/xadapt.hpp"
#include "xtensor/xio.hpp"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/factory.h"
#include "yacl/link/test_util.h"

using namespace yacl::crypto;
using yacl::link::Context;
using yacl::link::ContextDesc;

std::vector<int> ValueToBitVector(const spu::Value& val) {
  const auto& data = val.data();
  const int32_t numel = data.numel();
  const int32_t elsize = data.elsize();

  std::vector<int> result;
  result.reserve(numel);

  const uint8_t* raw_buf = reinterpret_cast<const uint8_t*>(data.buf()->data());
  for (int64_t i = 0; i < numel; ++i) {
    uint8_t byte = raw_buf[i * elsize];
    result.push_back(byte & 1);
  }
  return result;
}

std::shared_ptr<Context> MakeLink(const std::string& parties,
                                  size_t self_rank) {
  ContextDesc desc;
  std::vector<std::string> hosts = absl::StrSplit(parties, ',');
  for (size_t i = 0; i < hosts.size(); ++i) {
    desc.parties.emplace_back(fmt::format("party{}", i), hosts[i]);
  }
  return yacl::link::FactoryBrpc().CreateContext(desc, self_rank);
}

std::vector<int> RunOnePartyEquality(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint32_t>& input, size_t rank) {
  spu::RuntimeConfig config;
  config.set_protocol(spu::ProtocolKind::SEMI2K);
  config.set_field(spu::FieldType::FM32);
  spu::populateRuntimeConfig(config);
  config.set_enable_action_trace(false);
  config.set_enable_type_checker(false);

  auto sctx = std::make_shared<spu::SPUContext>(config, ctx);
  spu::mpc::Factory::RegisterProtocol(sctx.get(), ctx);

  spu::device::ColocatedIo cio(sctx.get());
  xt::xarray<uint32_t> input_x = xt::adapt(input);
  cio.hostSetVar(fmt::format("input-{}", rank), input_x);
  cio.sync();

  auto a = cio.deviceGetVar("input-0");
  auto b = cio.deviceGetVar("input-1");
  auto eq = spu::kernel::hlo::Equal(sctx.get(), a, b);
  return ValueToBitVector(eq);
}

int main() {
  size_t n = (1 << 22) * 1;
  std::cout << "Running PEQT with n = " << n << std::endl;
  std::vector<uint32_t> input_a = yacl::crypto::RandVec<uint32_t>(n);
  std::vector<uint32_t> input_b = yacl::crypto::RandVec<uint32_t>(n);
  auto lctxs = yacl::link::test::SetupWorld(2);
  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<std::vector<int>> fut0 = std::async(std::launch::async, [&] {
    return RunOnePartyEquality(lctxs[0], input_a, 0);
  });
  std::future<std::vector<int>> fut1 = std::async(std::launch::async, [&] {
    return RunOnePartyEquality(lctxs[1], input_b, 1);
  });

  auto result0 = fut0.get();
  auto result1 = fut1.get();

  auto end_time = std::chrono::high_resolution_clock::now();

  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                      end_time - start_time)
                      .count();
  std::cout << "Total execution time: " << duration << " ms" << std::endl;
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

  return 0;
}
