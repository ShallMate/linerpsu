#pragma once

#include <sys/types.h>

#include <cstddef>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/link/test_util.h"

namespace ps {

using namespace yacl::crypto;
using namespace std;
using namespace std::chrono;

std::vector<uint128_t> PSSend(const std::shared_ptr<yacl::link::Context>& ctx,
                              std::vector<size_t>& pi,
                              std::vector<uint128_t>& fxs);

std::vector<uint128_t> PSRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                              std::vector<uint128_t>& fxr,
                              std::vector<uint128_t>& rr, uint128_t k);
}  // namespace ps