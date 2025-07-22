
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
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
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

namespace psu {

constexpr size_t KAPPA = 128;

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

std::vector<uint128_t> PSUSend(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               CuckooHash& T_X, uint32_t cuckoolen,
                               okvs::Baxos baxos, okvs::Baxos baxos2) {
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(r), "r");
  // cout<< "cuckoolen: " << cuckoolen << endl;

  T_X.Insert(elem_hashes);
  T_X.Transform(r);

  size_t okvssize = baxos.size();
  uint128_t t1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "t1"));

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

  size_t n = cuckoolen;
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_B(n);
  std::vector<uint128_t> all_D(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_A[idx], a_keys.data(), T_X.bins_[idx]);
      aes128_encrypt_batch(all_B[idx], b_keys.data(), T_X.bins_[idx]);
      all_D[idx] = all_A[idx] ^ all_B[idx];
    }
  });

  std::vector<uint128_t> p(okvssize);

  baxos.Solve(absl::MakeSpan(T_X.bins_), absl::MakeSpan(all_D),
              absl::MakeSpan(p), nullptr, 8);

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p.data(), p.size() * sizeof(uint128_t)),
      "Send P");

  uint128_t omega_2 = yacl::crypto::FastRandU128();
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_2), "omega_2");
  uint128_t omega_1 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_1"));
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  if (t1 != t_11) {
    throw std::runtime_error("t1 mismatch");
  }
  uint128_t omega = omega_1 ^ omega_2;
  std::vector<uint128_t> receivermasks(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = all_A[idx] ^ omega;
    }
  });
  uint128_t okvssize2 = baxos2.size();
  std::vector<uint128_t> pp(okvssize2);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive PP");
  std::memcpy(pp.data(), buf.data(), buf.size());
  std::vector<uint128_t> rs(cuckoolen);
  baxos2.Decode(absl::MakeSpan(T_X.bins_), absl::MakeSpan(rs),
                absl::MakeSpan(pp), 8);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      rs[idx] = rs[idx] ^ receivermasks[idx];
    }
  });
  return rs;
}

std::vector<uint128_t> PSURecv(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               uint32_t cuckoolen, okvs::Baxos baxos,
                               okvs::Baxos baxos2) {
  // cout<< "cuckoolen: " << cuckoolen << endl;
  uint128_t r = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "r"));
  std::vector<uint128_t> T_Y(elem_hashes.size() * 3);

  std::vector<uint128_t> rs = RandVec<uint128_t>(cuckoolen);
  std::vector<uint128_t> RS(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    // cout<< "cuckoolen: " << cuckoolen << endl;
    // Process each element in elem_hashes
    for (int64_t idx = begin; idx < end; ++idx) {
      __m128i x_block =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(&elem_hashes[idx]));
      size_t idx1 = idx * 3;
      uint64_t h = GetHash(1, elem_hashes[idx]) % cuckoolen;
      T_Y[idx1] = Oracle(1, key_block, x_block);
      RS[idx1] = rs[h];
      h = GetHash(2, elem_hashes[idx]) % cuckoolen;
      T_Y[idx1 + 1] = Oracle(2, key_block, x_block);
      RS[idx1 + 1] = rs[h];
      h = GetHash(3, elem_hashes[idx]) % cuckoolen;
      T_Y[idx1 + 2] = Oracle(3, key_block, x_block);
      RS[idx1 + 2] = rs[h];
    }
  });

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(t_1), "t_1");

  size_t okvssize = baxos.size();
  auto s = yacl::crypto::SecureRandBits(KAPPA);
  uint128_t suint = s.data()[0];

  // === OT Recv ===
  std::vector<uint128_t> c_keys(KAPPA);
  std::future<void> receiver = std::async(
      [&] { yacl::crypto::BaseOtRecv(ctx, s, absl::MakeSpan(c_keys)); });
  receiver.get();

  // === AES Encrypt ===
  size_t n = T_Y.size();

  std::vector<uint128_t> all_C(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aes128_encrypt_batch(all_C[idx], c_keys.data(), T_Y[idx]);
    }
  });

  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");

  std::memcpy(p.data(), buf.data(), buf.size());

  // Receive omega_2
  uint128_t omega_2 = DeserializeUint128(ctx->Recv(ctx->PrevRank(), "omega_2"));

  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(omega_1), "omega_1");
  uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(absl::MakeSpan(T_Y), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p), 8);

  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] =
          RS[idx] ^ ((sendermasks[idx] & suint) ^ all_C[idx] ^ omega);
    }
  });
  uint128_t okvssize2 = baxos2.size();
  std::vector<uint128_t> pp(okvssize2);
  baxos2.Solve(absl::MakeSpan(T_Y), absl::MakeSpan(sendermasks),
               absl::MakeSpan(pp), nullptr, 8);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(pp.data(), pp.size() * sizeof(uint128_t)), "PP");
  return rs;
}
}  // namespace psu