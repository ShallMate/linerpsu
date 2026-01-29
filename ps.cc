
#include <sys/types.h>

#include <cstddef>
#include <vector>

#include "examples/linerpsu/utils.h"
#include "secure-join/Defines.h"
#include "secure-join/Prf/AltModPrf.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/serialize.h"

namespace ps {

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

// C[idx] = fxs[idx] ^ D[idx1]
// rr[idx]^A[idx];
std::vector<uint128_t> PSSend(const std::shared_ptr<yacl::link::Context>& ctx,
                              std::vector<size_t>& pi,
                              std::vector<uint128_t>& fxs) {
  size_t n = pi.size();
  std::vector<uint128_t> D(n);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive D");

  std::memcpy(D.data(), buf.data(), buf.size());

  std::vector<uint128_t> C(n);
  for (size_t idx = 0; idx < n; ++idx) {
    size_t idx1 = pi[idx];
    C[idx] = fxs[idx] ^ D[idx1];
  }
  return C;
}

std::vector<uint128_t> PSRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                              std::vector<uint128_t>& fxr,
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
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(D.data(), D.size() * sizeof(uint128_t)),
      "Send D");
  return fxr;
}

}  // namespace ps