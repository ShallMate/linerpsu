#pragma once

#include <cstddef>
#include <vector>

#include "examples/linerpsu/band_okvs_adapter.h"
#include "examples/linerpsu/cuckoohash.h"
#include "examples/linerpsu/okvs/baxos.h"
#include "coproto/Socket/Socket.h"
#include "yacl/base/int128.h"

namespace psu {

std::vector<uint128_t> PSURecv(coproto::Socket& sock,
                               const std::vector<uint128_t>& elem_hashes,
                               uint32_t cuckoolen, okvs::Baxos baxos,
                               okvs::Baxos baxos2);

std::vector<uint128_t> PSUSend(coproto::Socket& sock,
                               std::vector<uint128_t> elem_hashes,
                               CuckooHash& T_X, uint32_t cuckoolen,
                               okvs::Baxos baxos, okvs::Baxos baxos2);

std::vector<uint128_t> PSURecv(coproto::Socket& sock,
                               const std::vector<uint128_t>& elem_hashes,
                               uint32_t cuckoolen,
                               linerpsu::bandokvs::BandOkvs okvs,
                               linerpsu::bandokvs::BandOkvs okvs2);

std::vector<uint128_t> PSUSend(coproto::Socket& sock,
                               std::vector<uint128_t> elem_hashes,
                               CuckooHash& T_X, uint32_t cuckoolen,
                               linerpsu::bandokvs::BandOkvs okvs,
                               linerpsu::bandokvs::BandOkvs okvs2);

}  // namespace psu
