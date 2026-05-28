#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"

namespace linerpsu::bench_items {

struct ItemSets {
  std::vector<uint128_t> sender;
  std::vector<uint128_t> receiver;
  uint64_t intersection_size = 0;
};

inline std::vector<uint128_t> CreateRangeItems(uint64_t begin, uint64_t size) {
  YACL_ENFORCE(size <= static_cast<uint64_t>(std::numeric_limits<size_t>::max()),
               "item range too large: {}", size);
  std::vector<uint128_t> ret;
  ret.reserve(static_cast<size_t>(size));
  for (uint64_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

inline ItemSets CreateBenchmarkItemSets(uint64_t sender_size,
                                        uint64_t receiver_size,
                                        uint64_t diff) {
  const uint64_t min_size = std::min(sender_size, receiver_size);
  YACL_ENFORCE(diff < min_size,
               "diff must be smaller than both party sizes, diff={}, min={}",
               diff, min_size);

  ItemSets sets;
  sets.intersection_size = min_size - diff;
  const uint64_t sender_unique = sender_size - sets.intersection_size;
  const uint64_t receiver_unique = receiver_size - sets.intersection_size;

  sets.sender = CreateRangeItems(0, sets.intersection_size);
  auto sender_tail = CreateRangeItems(sets.intersection_size, sender_unique);
  sets.sender.insert(sets.sender.end(), sender_tail.begin(), sender_tail.end());

  sets.receiver = CreateRangeItems(0, sets.intersection_size);
  const uint64_t receiver_unique_begin =
      sets.intersection_size + sender_unique;
  auto receiver_tail =
      CreateRangeItems(receiver_unique_begin, receiver_unique);
  sets.receiver.insert(sets.receiver.end(), receiver_tail.begin(),
                       receiver_tail.end());
  return sets;
}

}  // namespace linerpsu::bench_items
