#pragma once

#include <sys/types.h>

#include <cstddef>
#include <vector>

#include "coproto/Socket/Socket.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"

namespace ps {

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

std::vector<uint128_t> PSSend(coproto::Socket& sock, std::vector<size_t>& pi,
                              std::vector<uint128_t>& fxs);

std::vector<uint128_t> PSRecv(coproto::Socket& sock, std::vector<uint128_t>& fxr,
                              std::vector<uint128_t>& rr, uint128_t k);
}  // namespace ps
