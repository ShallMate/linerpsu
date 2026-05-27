#pragma once



















#include "examples/linerpsu/GMW/Defines.h"
#include "examples/linerpsu/GMW/config.h"
#include "cryptoTools/Common/Timer.h"
#ifdef VOLE_PSI_ENABLE_GMW

#include <array>
#include <memory>

namespace volePSI {

#ifndef LIBOTE_HAS_STATIONARY_SILENT_OT
Proto generateBase(RequiredBase base, u64 partyIdx, oc::PRNG& prng,
                   coproto::Socket& chl, span<block> recvMsg,
                   span<std::array<block, 2>> sendMsg,
                   oc::Timer* timer = nullptr);

Proto extend(RequiredBase b, span<std::array<block, 2>> baseMsg,
             oc::PRNG& prng, coproto::Socket& chl, span<block> recvMsgP,
             span<std::array<block, 2>> sendMsgP);

Proto extend(RequiredBase b, oc::BitVector baseChoice, span<block> baseMsg,
             oc::PRNG& prng, coproto::Socket& chl, span<block> recvMsgP,
             span<std::array<block, 2>> sendMsgP);
#endif

class SilentTripleGen {
 public:
  SilentTripleGen();
  ~SilentTripleGen();
  SilentTripleGen(SilentTripleGen&&) noexcept;
  SilentTripleGen& operator=(SilentTripleGen&&) noexcept;
  SilentTripleGen(const SilentTripleGen&) = delete;
  SilentTripleGen& operator=(const SilentTripleGen&) = delete;

  void init(u64 n, u64 batchSize, u64 numThreads, Mode mode, block seed);
  void setTimer(oc::Timer& timer);

#ifndef LIBOTE_HAS_STATIONARY_SILENT_OT
  RequiredBase requiredBaseOts();

  void setBaseOts(span<block> recvOts, span<std::array<block, 2>> sendOts);
#endif

  Proto expand(coproto::Socket& chl);

  bool hasBaseOts() const;

  Proto generateBaseOts(u64 partyIdx, coproto::Socket& chl);

  block* multData();
  u64 multSize() const;
  block* addData();
  u64 addSize() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> mImpl;
};

}
#endif
