
#include <sys/types.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "examples/linerpsu/band_okvs_adapter.h"
#include "examples/linerpsu/cuckoohash.h"
#include "examples/linerpsu/debug_logging.h"
#include "examples/linerpsu/okvs/baxos.h"
#include "examples/linerpsu/opprf_hash.h"
#include "examples/linerpsu/socket_io.h"
#include "examples/linerpsu/utils.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Base/BaseOT.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/serialize.h"

namespace psu {

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

namespace {

void BaseOtSend(coproto::Socket& sock, size_t hb_bits,
                std::vector<std::array<uint128_t, 2>>* out) {
  debug::Log("base ot send start");
  std::vector<std::array<block, 2>> send_blocks(hb_bits);
  osuCrypto::DefaultBaseOT base_ot;
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
  coproto::sync_wait(base_ot.send(send_blocks, prng, sock));
  linerpsu::socket_io::Flush(sock);
  out->resize(hb_bits);
  for (size_t i = 0; i < hb_bits; ++i) {
    (*out)[i][0] = BlockToU128(send_blocks[i][0]);
    (*out)[i][1] = BlockToU128(send_blocks[i][1]);
  }
  debug::Log("base ot send done");
}

void BaseOtRecv(coproto::Socket& sock, size_t hb_bits,
                osuCrypto::BitVector* choices, uint128_t* choice_mask,
                std::vector<uint128_t>* out) {
  debug::Log("base ot recv start");
  choices->resize(hb_bits);
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
  choices->randomize(prng);
  *choice_mask = 0;
  for (size_t i = 0; i < hb_bits; ++i) {
    if ((*choices)[i]) {
      *choice_mask |= (static_cast<uint128_t>(1) << i);
    }
  }

  std::vector<block> recv_blocks(hb_bits);
  osuCrypto::DefaultBaseOT base_ot;
  coproto::sync_wait(base_ot.receive(*choices, recv_blocks, prng, sock));
  linerpsu::socket_io::Flush(sock);
  out->resize(hb_bits);
  for (size_t i = 0; i < hb_bits; ++i) {
    (*out)[i] = BlockToU128(recv_blocks[i]);
  }
  debug::Log("base ot recv done");
}

}  // namespace

std::vector<uint128_t> PSUSend(coproto::Socket& sock,
                               std::vector<uint128_t> elem_hashes,
                               CuckooHash& T_X, uint32_t cuckoolen,
                               okvs::Baxos baxos, okvs::Baxos baxos2) {
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  debug::Log("psu send r");
  linerpsu::socket_io::SendValue(sock, r);
  // cout<< "cuckoolen: " << cuckoolen << endl;

  T_X.Insert(std::move(elem_hashes));
  T_X.Transform(r);

  size_t okvssize = baxos.size();
  debug::Log("psu send wait t1");
  uint128_t t1 = linerpsu::socket_io::RecvValue<uint128_t>(sock);

  const size_t hb_bits = linerpsu::opprf_hash::EffectiveHbBits();
  std::vector<std::array<uint128_t, 2>> send_blocks;
  BaseOtSend(sock, hb_bits, &send_blocks);
  // === Extract OT keys ===
  std::vector<uint128_t> a_keys(hb_bits);
  std::vector<uint128_t> b_keys(hb_bits);
  for (size_t i = 0; i < hb_bits; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  // === AES Encryption ===

  size_t n = cuckoolen;
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_D(n);
  linerpsu::opprf_hash::EvalAAndDMany(all_A.data(), all_D.data(),
                                      a_keys.data(), b_keys.data(),
                                      T_X.bins_.data(), n, hb_bits);

  std::vector<uint128_t> p(okvssize);

  baxos.Solve(absl::MakeSpan(T_X.bins_), absl::MakeSpan(all_D),
              absl::MakeSpan(p), nullptr);

  debug::Log("psu send P");
  linerpsu::socket_io::SendVector(sock, p);

  uint128_t omega_2 = yacl::crypto::FastRandU128();
  linerpsu::socket_io::SendValue(sock, omega_2);
  uint128_t omega_1 = linerpsu::socket_io::RecvValue<uint128_t>(sock);
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  if (t1 != t_11) {
    throw std::runtime_error("t1 mismatch");
  }
  uint128_t omega = omega_1 ^ omega_2;
  std::vector<uint128_t> receivermasks(n);
  for (size_t idx = 0; idx < n; ++idx) {
    receivermasks[idx] = all_A[idx] ^ omega;
  }
  size_t okvssize2 = baxos2.size();
  std::vector<uint128_t> pp(okvssize2);
  debug::Log("psu send wait PP");
  pp = linerpsu::socket_io::RecvVector<uint128_t>(sock, okvssize2);
  std::vector<uint128_t> rs(cuckoolen);
  baxos2.Decode(absl::MakeSpan(T_X.bins_), absl::MakeSpan(rs),
                absl::MakeSpan(pp));
  for (size_t idx = 0; idx < n; ++idx) {
    rs[idx] = rs[idx] ^ receivermasks[idx];
  }
  return rs;
}

std::vector<uint128_t> PSURecv(coproto::Socket& sock,
                               const std::vector<uint128_t>& elem_hashes,
                               uint32_t cuckoolen, okvs::Baxos baxos,
                               okvs::Baxos baxos2) {
  // cout<< "cuckoolen: " << cuckoolen << endl;
  debug::Log("psu recv wait r");
  uint128_t r = linerpsu::socket_io::RecvValue<uint128_t>(sock);
  std::vector<uint128_t> T_Y(elem_hashes.size() * 3);

  std::vector<uint128_t> rs = RandVec<uint128_t>(cuckoolen);
  std::vector<uint128_t> RS(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  for (size_t idx = 0; idx < elem_hashes.size(); ++idx) {
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

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  debug::Log("psu recv send t1");
  linerpsu::socket_io::SendValue(sock, t_1);

  size_t okvssize = baxos.size();

  // === OT Recv ===
  osuCrypto::BitVector choices;
  uint128_t suint = 0;
  std::vector<uint128_t> c_keys;
  const size_t hb_bits = linerpsu::opprf_hash::EffectiveHbBits();
  BaseOtRecv(sock, hb_bits, &choices, &suint, &c_keys);

  // === AES Encrypt ===
  size_t n = T_Y.size();

  std::vector<uint128_t> all_C(n);
  linerpsu::opprf_hash::EvalMany(all_C.data(), c_keys.data(), T_Y.data(), n,
                                 hb_bits);
  debug::Log("psu recv wait P");
  std::vector<uint128_t> p =
      linerpsu::socket_io::RecvVector<uint128_t>(sock, okvssize);

  // Receive omega_2
  uint128_t omega_2 = linerpsu::socket_io::RecvValue<uint128_t>(sock);

  linerpsu::socket_io::SendValue(sock, omega_1);
  uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);
  baxos.Decode(absl::MakeSpan(T_Y), absl::MakeSpan(sendermasks),
               absl::MakeSpan(p));
  for (size_t idx = 0; idx < n; ++idx) {
    sendermasks[idx] =
        RS[idx] ^ ((sendermasks[idx] & suint) ^ all_C[idx] ^ omega);
  }

  size_t okvssize2 = baxos2.size();
  std::vector<uint128_t> pp(okvssize2);
  baxos2.Solve(absl::MakeSpan(T_Y), absl::MakeSpan(sendermasks),
               absl::MakeSpan(pp), nullptr);
  debug::Log("psu recv send PP");
  linerpsu::socket_io::SendVector(sock, pp);
  return rs;
}

std::vector<uint128_t> PSUSend(coproto::Socket& sock,
                               std::vector<uint128_t> elem_hashes,
                               CuckooHash& T_X, uint32_t cuckoolen,
                               linerpsu::bandokvs::BandOkvs okvs,
                               linerpsu::bandokvs::BandOkvs okvs2) {
  uint128_t r = yacl::crypto::FastRandU128();
  // Generate a random seed omega_1 for the first hash
  linerpsu::socket_io::SendValue(sock, r);
  // cout<< "cuckoolen: " << cuckoolen << endl;

  T_X.Insert(std::move(elem_hashes));
  T_X.Transform(r);

  size_t okvssize = okvs.Size();
  uint128_t t1 = linerpsu::socket_io::RecvValue<uint128_t>(sock);

  const size_t hb_bits = linerpsu::opprf_hash::EffectiveHbBits();
  std::vector<std::array<uint128_t, 2>> send_blocks;
  BaseOtSend(sock, hb_bits, &send_blocks);
  // === Extract OT keys ===
  std::vector<uint128_t> a_keys(hb_bits);
  std::vector<uint128_t> b_keys(hb_bits);
  for (size_t i = 0; i < hb_bits; ++i) {
    a_keys[i] = send_blocks[i][0];
    b_keys[i] = send_blocks[i][1];
  }

  // === AES Encryption ===

  size_t n = cuckoolen;
  std::vector<uint128_t> all_A(n);
  std::vector<uint128_t> all_D(n);
  linerpsu::opprf_hash::EvalAAndDMany(all_A.data(), all_D.data(),
                                      a_keys.data(), b_keys.data(),
                                      T_X.bins_.data(), n, hb_bits);

  std::vector<uint128_t> p(okvssize);

  okvs.Encode(absl::MakeSpan(T_X.bins_), absl::MakeSpan(all_D),
              absl::MakeSpan(p));

  linerpsu::socket_io::SendVector(sock, p);

  uint128_t omega_2 = yacl::crypto::FastRandU128();
  linerpsu::socket_io::SendValue(sock, omega_2);
  uint128_t omega_1 = linerpsu::socket_io::RecvValue<uint128_t>(sock);
  uint128_t t_11 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  if (t1 != t_11) {
    throw std::runtime_error("t1 mismatch");
  }
  uint128_t omega = omega_1 ^ omega_2;
  std::vector<uint128_t> receivermasks(n);
  for (size_t idx = 0; idx < n; ++idx) {
    receivermasks[idx] = all_A[idx] ^ omega;
  }
  size_t okvssize2 = okvs2.Size();
  std::vector<uint128_t> pp(okvssize2);
  pp = linerpsu::socket_io::RecvVector<uint128_t>(sock, okvssize2);
  std::vector<uint128_t> rs(cuckoolen);
  okvs2.Decode(absl::MakeSpan(T_X.bins_), absl::MakeSpan(pp),
               absl::MakeSpan(rs));
  for (size_t idx = 0; idx < n; ++idx) {
    rs[idx] = rs[idx] ^ receivermasks[idx];
  }
  return rs;
}

std::vector<uint128_t> PSURecv(coproto::Socket& sock,
                               const std::vector<uint128_t>& elem_hashes,
                               uint32_t cuckoolen,
                               linerpsu::bandokvs::BandOkvs okvs,
                               linerpsu::bandokvs::BandOkvs okvs2) {
  // cout<< "cuckoolen: " << cuckoolen << endl;
  uint128_t r = linerpsu::socket_io::RecvValue<uint128_t>(sock);
  std::vector<uint128_t> T_Y(elem_hashes.size() * 3);

  std::vector<uint128_t> rs = RandVec<uint128_t>(cuckoolen);
  std::vector<uint128_t> RS(elem_hashes.size() * 3);
  __m128i key_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&r));
  for (size_t idx = 0; idx < elem_hashes.size(); ++idx) {
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

  uint128_t omega_1 = yacl::crypto::FastRandU128();
  uint128_t t_1 = yacl::crypto::Blake3_128(yacl::SerializeUint128(omega_1));
  linerpsu::socket_io::SendValue(sock, t_1);

  size_t okvssize = okvs.Size();

  // === OT Recv ===
  osuCrypto::BitVector choices;
  uint128_t suint = 0;
  std::vector<uint128_t> c_keys;
  const size_t hb_bits = linerpsu::opprf_hash::EffectiveHbBits();
  BaseOtRecv(sock, hb_bits, &choices, &suint, &c_keys);

  // === AES Encrypt ===
  size_t n = T_Y.size();

  std::vector<uint128_t> all_C(n);
  linerpsu::opprf_hash::EvalMany(all_C.data(), c_keys.data(), T_Y.data(), n,
                                 hb_bits);
  std::vector<uint128_t> p =
      linerpsu::socket_io::RecvVector<uint128_t>(sock, okvssize);

  // Receive omega_2
  uint128_t omega_2 = linerpsu::socket_io::RecvValue<uint128_t>(sock);

  linerpsu::socket_io::SendValue(sock, omega_1);
  uint128_t omega = omega_1 ^ omega_2;

  std::vector<uint128_t> sendermasks(n);
  okvs.Decode(absl::MakeSpan(T_Y), absl::MakeSpan(p),
              absl::MakeSpan(sendermasks));
  for (size_t idx = 0; idx < n; ++idx) {
    sendermasks[idx] =
        RS[idx] ^ ((sendermasks[idx] & suint) ^ all_C[idx] ^ omega);
  }

  std::vector<uint128_t> pp(okvs2.Size());
  okvs2.Encode(absl::MakeSpan(T_Y), absl::MakeSpan(sendermasks),
               absl::MakeSpan(pp));
  linerpsu::socket_io::SendVector(sock, pp);
  return rs;
}
}  // namespace psu
