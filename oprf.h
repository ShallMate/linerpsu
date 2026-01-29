#pragma once
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
#include "yacl/utils/serialize.h"

namespace oprf {

std::vector<uint128_t> OPRFRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<uint128_t>& elem_hashes,
                                okvs::Baxos baxos);

void OPRFSend(const std::shared_ptr<yacl::link::Context>& ctx,
              std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos);

}  // namespace oprf