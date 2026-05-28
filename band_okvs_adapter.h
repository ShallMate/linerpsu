#pragma once

#include <cstddef>
#include <vector>

#include "absl/types/span.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

namespace linerpsu::bandokvs {

inline bool CpuSupportsAvx512F() {
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
  return __builtin_cpu_supports("avx512f");
#else
  return false;
#endif
}

inline void EnsureSupported() {
  YACL_ENFORCE(CpuSupportsAvx512F(),
               "bandokvs backend requires AVX-512F support");
}

class BandOkvs {
 public:
  explicit BandOkvs(size_t programmed_items);

  size_t Size() const;
  size_t NumVars() const { return static_cast<size_t>(num_vars_); }
  size_t ProgrammedItems() const { return programmed_items_; }
  int BandLength() const { return band_length_; }

  void Encode(absl::Span<const uint128_t> keys,
              absl::Span<const uint128_t> values,
              absl::Span<uint128_t> output) const;

  void Decode(absl::Span<const uint128_t> keys,
              absl::Span<const uint128_t> okvs,
              absl::Span<uint128_t> output) const;

 private:
  size_t programmed_items_ = 0;
  int num_vars_ = 0;
  int band_length_ = 0;
};

}  // namespace linerpsu::bandokvs
