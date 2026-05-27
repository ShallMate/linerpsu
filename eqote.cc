#include "examples/linerpsu/eqote.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <array>
#include <stdexcept>
#include <string>
#include <vector>

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "examples/linerpsu/socket_io.h"
#include "examples/linerpsu/utils.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

namespace eqote {

using namespace std;

namespace {

osuCrypto::MultType ParseSilentOtCode(const std::string& code) {
  if (code == "tungsten" || code == "Tungsten") {
    return osuCrypto::MultType::Tungsten;
  }
  if (code == "exconv7" || code == "ExConv7x24") {
    return osuCrypto::MultType::ExConv7x24;
  }
  if (code == "exconv21" || code == "ExConv21x24") {
    return osuCrypto::MultType::ExConv21x24;
  }
  if (code == "exacc7" || code == "ExAcc7") {
    return osuCrypto::MultType::ExAcc7;
  }
  if (code == "exacc11" || code == "ExAcc11") {
    return osuCrypto::MultType::ExAcc11;
  }
  if (code == "exacc21" || code == "ExAcc21") {
    return osuCrypto::MultType::ExAcc21;
  }
  if (code == "exacc40" || code == "ExAcc40") {
    return osuCrypto::MultType::ExAcc40;
  }
  if (code == "qc" || code == "quasi" || code == "QuasiCyclic") {
    return osuCrypto::MultType::QuasiCyclic;
  }
  throw std::runtime_error("unsupported LINERPSU_SILENT_OT_CODE=" + code);
}

osuCrypto::MultType SilentOtCode() {
  const char* env = std::getenv("LINERPSU_SILENT_OT_CODE");
  return ParseSilentOtCode(env == nullptr ? "Tungsten" : std::string(env));
}

osuCrypto::BitVector ToBitVector(const std::vector<bool>& bits) {
  osuCrypto::BitVector out(bits.size());
  for (size_t i = 0; i < bits.size(); ++i) {
    out[i] = bits[i];
  }
  return out;
}

void Configure(osuCrypto::SilentOtExtSender& sender, size_t n) {
  sender.mMultType = SilentOtCode();
  sender.configure(static_cast<osuCrypto::u64>(n), 2, 1,
                   osuCrypto::SilentSecType::SemiHonest);
}

void Configure(osuCrypto::SilentOtExtReceiver& receiver, size_t n) {
  receiver.mMultType = SilentOtCode();
  receiver.configure(static_cast<osuCrypto::u64>(n), 2, 1,
                     osuCrypto::SilentSecType::SemiHonest);
}

}  // namespace

vector<uint128_t> EQOTERecv(coproto::Socket& sock,
                            const std::vector<bool>& eqr) {
  const size_t num_ot = eqr.size();
  auto choices = ToBitVector(eqr);
  std::vector<block> recv_msgs(num_ot);

  osuCrypto::SilentOtExtReceiver receiver;
  Configure(receiver, num_ot);
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
  coproto::sync_wait(receiver.genBaseOts(prng, sock));
  coproto::sync_wait(receiver.receive(choices, recv_msgs, prng, sock));

  auto ciphers0 =
      linerpsu::socket_io::RecvVector<uint128_t>(sock, num_ot);
  auto ciphers1 =
      linerpsu::socket_io::RecvVector<uint128_t>(sock, num_ot);

  std::vector<uint128_t> outputs;
  outputs.reserve(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    const uint128_t cipher = eqr[i] ? ciphers1[i] : ciphers0[i];
    const uint128_t elem = cipher ^ BlockToU128(recv_msgs[i]);
    if (elem != 0) {
      outputs.push_back(elem);
    }
  }
  return outputs;
}

void EQOTESend(coproto::Socket& sock, const std::vector<bool>& eqs,
               const std::vector<uint128_t>& elems) {
  const size_t num_ot = eqs.size();
  YACL_ENFORCE(elems.size() == num_ot, "EQOTE elems size mismatch");

  std::vector<std::array<block, 2>> sender_msgs(num_ot);
  osuCrypto::SilentOtExtSender sender;
  Configure(sender, num_ot);
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
  coproto::sync_wait(sender.genBaseOts(prng, sock));
  coproto::sync_wait(sender.send(sender_msgs, prng, sock));

  std::vector<uint128_t> ciphers0(num_ot);
  std::vector<uint128_t> ciphers1(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    const uint128_t elem = elems[i];
    const uint128_t m0 = eqs[i] ? 0 : elem;
    const uint128_t m1 = eqs[i] ? elem : 0;
    ciphers0[i] = m0 ^ BlockToU128(sender_msgs[i][0]);
    ciphers1[i] = m1 ^ BlockToU128(sender_msgs[i][1]);
  }
  linerpsu::socket_io::SendVector(sock, ciphers0);
  linerpsu::socket_io::SendVector(sock, ciphers1);
}

}  // namespace eqote
