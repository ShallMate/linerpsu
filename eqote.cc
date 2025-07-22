
#include <sys/types.h>
#include <cstddef>

#include <vector>

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"
#include "yacl/link/test_util.h"

namespace eqote {

using namespace yacl::crypto;
using namespace std;

vector<uint128_t> OTERecv(const std::shared_ptr<yacl::link::Context>& ctx,const std::vector<bool>& chooses) {
  size_t num_ot = chooses.size();
  auto ss_receiver = yacl::crypto::SoftspokenOtExtReceiver();
  auto rand_bits = yacl::crypto::SecureRandBits(num_ot);
  auto store = ss_receiver.GenRot(ctx, rand_bits);
  yacl::dynamic_bitset<> bbs(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    bbs[i] = chooses[i]^ rand_bits[i];
   }
   std::string bbs_str = bbs.to_string();    
  ctx->SendAsync(ctx->NextRank(), yacl::ByteContainerView(bbs_str), "Send bitset string");

  auto buf = ctx->Recv(ctx->PrevRank(), "Recv ciphertexts0");
  auto buf1 = ctx->Recv(ctx->PrevRank(), "Recv ciphertexts1");
  std::vector<uint128_t> ciphers0(num_ot);
  std::vector<uint128_t> ciphers1(num_ot);
  std::memcpy(ciphers0.data(), buf.data(), buf.size());
  std::memcpy(ciphers1.data(), buf1.data(), buf1.size());
  std::vector<uint128_t> elems(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
      if(chooses[i]) {
          elems[i] = ciphers1[i] ^ store.GetBlock(i);
      } else {
          elems[i] = ciphers0[i] ^ store.GetBlock(i);
      }
  }
  return elems;
}

void OTESend(const std::shared_ptr<yacl::link::Context>& ctx,
               const std::vector<uint128_t>& m0s,const std::vector<uint128_t>& m1s) {
  size_t num_ot = m0s.size();
  auto ss_sender = yacl::crypto::SoftspokenOtExtSender();
  auto store = ss_sender.GenRot(ctx, num_ot);
  auto buf = ctx->Recv(ctx->PrevRank(), "Send bbs_str");
  std::string bit_str(reinterpret_cast<const char*>(buf.data()), buf.size());
  yacl::dynamic_bitset<> bbs(bit_str); 

  std::vector<uint128_t> ciphers0(num_ot);
  std::vector<uint128_t> ciphers1(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    ciphers0[i] = m0s[i] ^ store.GetBlock(i, bbs[i] ? 1 : 0);
    ciphers1[i] = m1s[i] ^ store.GetBlock(i, bbs[i] ? 0 : 1);
  }
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(ciphers0.data(),
                                         ciphers0.size() * sizeof(uint128_t)),
                 "Send ciphertexts");
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(ciphers1.data(),
                                         ciphers1.size() * sizeof(uint128_t)),
                 "Send ciphertexts");
}

vector<uint128_t> EQOTERecv(const std::shared_ptr<yacl::link::Context>& ctx,const std::vector<bool>& eqr) {
  std::vector<uint128_t> outputs;
    auto recv_future = std::async(std::launch::async, [&] {
    outputs = OTERecv(ctx, eqr);
  });
  recv_future.get();
  outputs.erase(
    std::remove_if(outputs.begin(), outputs.end(),
                   [](const auto& x) { return x == 0;}),
    outputs.end());
  return outputs;
}

void EQOTESend(const std::shared_ptr<yacl::link::Context>& ctx,const std::vector<bool>& eqs,
               const std::vector<uint128_t>& elems) {
  size_t num_ot = eqs.size();
  std::vector<uint128_t> m0s(num_ot);
  std::vector<uint128_t> m1s(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
        if (eqs[i]) {
        m0s[i] = 0;
        m1s[i] = elems[i];
        } else {
        m0s[i] = elems[i];
        m1s[i] = 0;
        }
  }
  auto send_future = std::async(std::launch::async, [&] {
    OTESend(ctx, m0s, m1s);
  });
  send_future.get();
}
}