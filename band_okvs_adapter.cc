#include "examples/linerpsu/band_okvs_adapter.h"

#include <algorithm>
#include <cmath>
#include <cstdint>

#include "examples/linerpsu/bandokvs/band_okvs.h"
#include "cryptoTools/Common/Defines.h"

namespace linerpsu::bandokvs {

namespace {

constexpr double kTargetStatisticalSecurity = 40.0;
constexpr double kRateExpansion = 1.03;

struct BandFitLine {
  size_t logn;
  double slope;
  double intercept;
};

constexpr BandFitLine kEpsilon003FitLines[] = {
    {10, 0.08047, -3.464}, {14, 0.08253, -5.751},
    {16, 0.08241, -7.023}, {18, 0.08192, -8.569},
    {20, 0.08313, -10.880}, {24, 0.08253, -14.671},
};

oc::block FixedSeed() {
  return oc::block(0x13579BDF2468ACE0ULL, 0x0F1E2D3C4B5A6978ULL);
}

size_t CeilLog2(size_t value) {
  if (value <= 1) {
    return 0;
  }
  size_t logn = 0;
  --value;
  while (value > 0) {
    value >>= 1;
    ++logn;
  }
  return logn;
}

BandFitLine SelectFitLine(size_t programmed_items) {
  const size_t logn = CeilLog2(std::max<size_t>(1, programmed_items));
  for (const auto& fit : kEpsilon003FitLines) {
    if (logn <= fit.logn) {
      return fit;
    }
  }

  // BPSY23 reports fit lines up to n=2^24. For larger local stress tests,
  // keep the n=2^24 slope and pessimistically decrease the intercept by the
  // n=2^20 -> 2^24 trend rather than silently dropping below 40-bit security.
  BandFitLine fit = kEpsilon003FitLines[sizeof(kEpsilon003FitLines) /
                                        sizeof(kEpsilon003FitLines[0]) - 1];
  const double intercept_drop_per_log2 =
      (-10.880 - (-14.671)) / static_cast<double>(24 - 20);
  fit.intercept -=
      static_cast<double>(logn - fit.logn) * intercept_drop_per_log2;
  fit.logn = logn;
  return fit;
}

int BandLengthFor(size_t programmed_items) {
  const auto fit = SelectFitLine(programmed_items);
  const double width =
      (kTargetStatisticalSecurity - fit.intercept) / fit.slope;
  return static_cast<int>(std::ceil(width));
}

int NumVarsFor(size_t programmed_items, int band_length) {
  const size_t non_empty_items = std::max<size_t>(1, programmed_items);
  const size_t scaled =
      static_cast<size_t>(std::ceil(kRateExpansion * non_empty_items));
  const size_t minimum = static_cast<size_t>(band_length + 1);
  return static_cast<int>(std::max(scaled, minimum));
}

band_okvs::BandOkvs MakeOkvs(size_t eqns, int num_vars, int band_length) {
  band_okvs::BandOkvs okvs;
  okvs.Init(static_cast<int>(std::max<size_t>(1, eqns)), num_vars, band_length,
            FixedSeed());
  return okvs;
}

}  // namespace

BandOkvs::BandOkvs(size_t programmed_items)
    : programmed_items_(programmed_items),
      num_vars_(NumVarsFor(programmed_items, BandLengthFor(programmed_items))),
      band_length_(BandLengthFor(programmed_items)) {}

size_t BandOkvs::Size() const {
  auto okvs = MakeOkvs(programmed_items_, num_vars_, band_length_);
  return static_cast<size_t>(okvs.Size());
}

void BandOkvs::Encode(absl::Span<const uint128_t> keys,
                      absl::Span<const uint128_t> values,
                      absl::Span<uint128_t> output) const {
  EnsureSupported();
  YACL_ENFORCE(keys.size() == values.size(),
               "bandokvs Encode key/value size mismatch: {} vs {}",
               keys.size(), values.size());
  YACL_ENFORCE(output.size() == Size(),
               "bandokvs Encode output size mismatch: got {}, want {}",
               output.size(), Size());
  auto okvs = MakeOkvs(keys.size(), num_vars_, band_length_);
  const bool ok = okvs.Encode(
      reinterpret_cast<const oc::block*>(keys.data()),
      reinterpret_cast<const oc::block*>(values.data()),
      reinterpret_cast<oc::block*>(output.data()));
  YACL_ENFORCE(ok, "bandokvs Encode failed");
}

void BandOkvs::Decode(absl::Span<const uint128_t> keys,
                      absl::Span<const uint128_t> okvs_payload,
                      absl::Span<uint128_t> output) const {
  EnsureSupported();
  YACL_ENFORCE(keys.size() == output.size(),
               "bandokvs Decode key/output size mismatch: {} vs {}",
               keys.size(), output.size());
  YACL_ENFORCE(okvs_payload.size() == Size(),
               "bandokvs Decode payload size mismatch: got {}, want {}",
               okvs_payload.size(), Size());
  auto okvs = MakeOkvs(keys.size(), num_vars_, band_length_);
  okvs.Decode(reinterpret_cast<const oc::block*>(keys.data()),
              reinterpret_cast<const oc::block*>(okvs_payload.data()),
              reinterpret_cast<oc::block*>(output.data()));
}

}  // namespace linerpsu::bandokvs
