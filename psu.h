#pragma once

#include <cstddef>
#include <vector>

#include "examples/linerpsu/bokvs.h"
#include "examples/linerpsu/cuckoohash.h"
#include "examples/linerpsu/okvs/baxos.h"
#include "yacl/base/int128.h"
#include "yacl/link/test_util.h"

namespace psu {

std::vector<uint128_t> PSURecv(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               uint32_t cuckoolen, okvs::Baxos baxos,
                               okvs::Baxos baxos2);

std::vector<uint128_t> PSUSend(const std::shared_ptr<yacl::link::Context>& ctx,
                               std::vector<uint128_t>& elem_hashes,
                               CuckooHash& T_X, uint32_t cuckoolen,
                               okvs::Baxos baxos, okvs::Baxos baxos2);

}  // namespace psu