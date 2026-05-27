
#include <sys/types.h>

#include <cstddef>
#include <vector>

#include "examples/linerpsu/socket_io.h"
#include "examples/linerpsu/utils.h"
#include "secure-join/Defines.h"
#include "secure-join/Prf/AltModPrf.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"

namespace ps {

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

// C[idx] = fxs[idx] ^ D[idx1]
// rr[idx]^A[idx];
std::vector<uint128_t> PSSend(coproto::Socket& sock, std::vector<size_t>& pi,
                              std::vector<uint128_t>& fxs) {
  size_t n = pi.size();
  std::vector<uint128_t> D =
      linerpsu::socket_io::RecvVector<uint128_t>(sock, n);

  std::vector<uint128_t> C(n);
  for (size_t idx = 0; idx < n; ++idx) {
    size_t idx1 = pi[idx];
    C[idx] = fxs[idx] ^ D[idx1];
  }
  return C;
}

std::vector<uint128_t> PSRecv(coproto::Socket& sock, std::vector<uint128_t>& fxr,
                              std::vector<uint128_t>& rr, uint128_t k) {
  size_t n = rr.size();
  std::vector<block> A(n);
  std::vector<uint128_t> D(n);
  auto kk = ExpandKey512FromSeed(k);
  secJoin::AltModPrf prf(kk);
  std::vector<block> X(n);
    for (u64 i = 0; i < n; ++i) { X[i] = block(static_cast<u64>(i), 0);
  }
  prf.eval(X, A);
  for (size_t idx = 0; idx < n; ++idx) {
    //A[idx] = yacl::crypto::Blake3_128(yacl::SerializeUint128(k ^ idx));
    D[idx] = rr[idx] ^ BlockToU128(A[idx]);
  }
  linerpsu::socket_io::SendVector(sock, D);
  return fxr;
}

}  // namespace ps
