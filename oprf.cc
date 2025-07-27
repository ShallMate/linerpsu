
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "examples/linerpsu/bokvs.h"
#include "examples/linerpsu/cuckoohash.h"
#include "examples/linerpsu/okvs/baxos.h"
#include "examples/linerpsu/utils.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/serialize.h"

namespace oprf {

constexpr size_t KAPPA = 128;

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

std::vector<uint128_t> OPRFRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                          std::vector<uint128_t>& elem_hashes,
                          okvs::Baxos baxos) {
  size_t okvssize = baxos.size();
  std::vector<std::array<uint128_t, 2>> send_blocks(KAPPA);
  std::future<void> sender = std::async(
      [&] { yacl::crypto::BaseOtSend(ctx, absl::MakeSpan(send_blocks)); });
  sender.get();

  // === Extract OT keys ===
  std::vector<uint128_t> a_keys(KAPPA);
  std::vector<uint128_t> b_keys(KAPPA);
  for (size_t i = 0; i < KAPPA; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  // === AES Encryption ===

  size_t n = elem_hashes.size();
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  for (size_t idx = 0; idx < n; ++idx) {
    aes128_encrypt_batch(all_A[idx], a_keys.data(), elem_hashes[idx]);
    aes128_encrypt_batch(all_B[idx], b_keys.data(), elem_hashes[idx]);
    all_D[idx] = all_A[idx] ^ all_B[idx];
  }
  std::vector<uint128_t> p(okvssize);

  baxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(all_D),
              absl::MakeSpan(p));

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p.data(), p.size() * sizeof(uint128_t)),
      "Send P");

  return all_A;

}

void OPRFSend(const std::shared_ptr<yacl::link::Context>& ctx,
             std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos) {

  size_t okvssize = baxos.size();
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  uint128_t suint = s.data()[0];

  // === OT Recv ===
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  // === AES Encrypt ===
  size_t n = elem_hashes.size();

  std::vector<uint128_t> all_C(n);
  for (size_t idx = 0; idx < n; ++idx) {
    aes128_encrypt_batch(all_C[idx], c_keys.data(), elem_hashes[idx]);
  }


  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");

  std::memcpy(p.data(), buf.data(), buf.size());




  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p));

  
    for (size_t idx = 0; idx < n; ++idx) {
      sendermasks[idx] = (sendermasks[idx] & suint) ^ all_C[idx];
    }
}

}  // namespace oprf