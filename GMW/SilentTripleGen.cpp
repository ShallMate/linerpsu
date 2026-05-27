#include "examples/linerpsu/GMW/SilentTripleGen.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"

#ifndef LIBOTE_HAS_STATIONARY_SILENT_OT
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#endif

namespace volePSI {

namespace {
void SetTimePoint(const char*) {}

void DebugLogSilentTriple(const std::string& msg) {
  if (const char *env = std::getenv("LINERPSU_DEBUG")) {
    if (env[0] != '\0' && !(env[0] == '0' && env[1] == '\0')) {
      static std::mutex mu;
      std::lock_guard<std::mutex> lock(mu);
      std::cerr << "[silent-triple] " << msg << std::endl;
    }
  }
}
}  // namespace

struct SilentTripleGen::Impl {
  bool mHasBase = false;
  u64 mN = 0;
  u64 mBatchSize = 0;
  u64 mNumBatchs = 0;
  u64 mNumPer = 0;
  bool mUseStationary = false;
  Mode mMode = Mode::Sender;
  oc::PRNG mPrng;

  span<block> mMult;
  span<block> mAdd;
  std::vector<block> mAVec;
  std::vector<block> mBVec;
  std::vector<block> mDVec;
  oc::BitVector mCBitVec;

  std::unique_ptr<oc::SilentOtExtSender[]> mBackingSenderOT;
  std::unique_ptr<oc::SilentOtExtReceiver[]> mBackingRecverOT;
  span<oc::SilentOtExtSender> mSenderOT;
  span<oc::SilentOtExtReceiver> mRecverOT;
#ifndef LIBOTE_HAS_STATIONARY_SILENT_OT
  RequiredBase mBase;
#endif
};

SilentTripleGen::SilentTripleGen() : mImpl(std::make_unique<Impl>()) {}

SilentTripleGen::~SilentTripleGen() = default;

SilentTripleGen::SilentTripleGen(SilentTripleGen&&) noexcept = default;

SilentTripleGen&
SilentTripleGen::operator=(SilentTripleGen&&) noexcept = default;

void SilentTripleGen::setTimer(oc::Timer& timer) {
  (void)timer;
}

bool SilentTripleGen::hasBaseOts() const {
  return mImpl && mImpl->mHasBase;
}

block* SilentTripleGen::multData() {
  return mImpl->mMult.data();
}

u64 SilentTripleGen::multSize() const {
  return mImpl->mMult.size();
}

block* SilentTripleGen::addData() {
  return mImpl->mAdd.data();
}

u64 SilentTripleGen::addSize() const {
  return mImpl->mAdd.size();
}

void SilentTripleGen::init(u64 n, u64 batchSize, u64 numThreads, Mode mode,
                           block seed) {
  if (!mImpl) {
    mImpl = std::make_unique<Impl>();
  }
  mImpl->mHasBase = false;
#ifndef LIBOTE_HAS_STATIONARY_SILENT_OT
  mImpl->mBase.mNumSend = 0;
  mImpl->mBase.mRecvChoiceBits = {};
#endif
  mImpl->mBackingSenderOT.reset();
  mImpl->mBackingRecverOT.reset();
  mImpl->mSenderOT = {};
  mImpl->mRecverOT = {};

  auto effective_batch_size = batchSize;
#ifdef LIBOTE_HAS_STATIONARY_SILENT_OT
  constexpr u64 kStationaryMinTotal = 1ull << 18;
  constexpr u64 kSingleBatchLimit = 1ull << 20;
  if (n <= kSingleBatchLimit) {
    effective_batch_size = std::max<u64>(effective_batch_size, n);
  }
#endif
  mImpl->mBatchSize = effective_batch_size;
  mImpl->mNumBatchs = (n + mImpl->mBatchSize - 1) / mImpl->mBatchSize;
  mImpl->mNumPer =
      oc::roundUpTo((n + mImpl->mNumBatchs - 1) / mImpl->mNumBatchs, 128);

  mImpl->mN = mImpl->mNumBatchs * mImpl->mNumPer;
  mImpl->mMode = mode;
  mImpl->mPrng.SetSeed(seed);

#ifdef LIBOTE_HAS_STATIONARY_SILENT_OT
  mImpl->mUseStationary = n >= kStationaryMinTotal;
  if (const char *env = std::getenv("LINERPSU_SILENT_NOISE")) {
    const auto noise = std::string_view(env);
    if (noise == "regular") {
      mImpl->mUseStationary = false;
    } else if (noise == "stationary") {
      mImpl->mUseStationary = true;
    }
  }
  const u64 numOtInstances = mImpl->mUseStationary ? 1 : mImpl->mNumBatchs;
#else
  mImpl->mUseStationary = false;
  const u64 numOtInstances = mImpl->mNumBatchs;
#endif

  DebugLogSilentTriple("n=" + std::to_string(n) +
                       ", batch_size=" + std::to_string(mImpl->mBatchSize) +
                       ", batches=" + std::to_string(mImpl->mNumBatchs) +
                       ", num_per=" + std::to_string(mImpl->mNumPer) +
                       ", noise=" +
                       (mImpl->mUseStationary ? "stationary" : "regular"));

  if (mode & Mode::Sender) {
    mImpl->mBackingSenderOT.reset(new oc::SilentOtExtSender[numOtInstances]);
    mImpl->mSenderOT = span<oc::SilentOtExtSender>(
        mImpl->mBackingSenderOT.get(), numOtInstances);
  }

  if (mode & Mode::Receiver) {
    mImpl->mBackingRecverOT.reset(
        new oc::SilentOtExtReceiver[numOtInstances]);
    mImpl->mRecverOT = span<oc::SilentOtExtReceiver>(
        mImpl->mBackingRecverOT.get(), numOtInstances);
  }

  for (u64 i = 0; i < mImpl->mSenderOT.size(); i++) {
#ifdef LIBOTE_HAS_STATIONARY_SILENT_OT
    mImpl->mSenderOT[i].configure(
        mImpl->mNumPer, 2, numThreads, oc::SilentSecType::SemiHonest,
        mImpl->mUseStationary ? oc::SdNoiseDistribution::Stationary
                              : oc::SdNoiseDistribution::Regular,
        oc::MultType::Tungsten);
#else
    mImpl->mSenderOT[i].mMultType = oc::MultType::Tungsten;
    mImpl->mSenderOT[i].configure(mImpl->mNumPer, 2, numThreads,
                                  oc::SilentSecType::SemiHonest);
#endif
  }
  for (u64 i = 0; i < mImpl->mRecverOT.size(); i++) {
#ifdef LIBOTE_HAS_STATIONARY_SILENT_OT
    mImpl->mRecverOT[i].configure(
        mImpl->mNumPer, 2, numThreads, oc::SilentSecType::SemiHonest,
        mImpl->mUseStationary ? oc::SdNoiseDistribution::Stationary
                              : oc::SdNoiseDistribution::Regular,
        oc::MultType::Tungsten);
#else
    mImpl->mRecverOT[i].mMultType = oc::MultType::Tungsten;
    mImpl->mRecverOT[i].configure(mImpl->mNumPer, 2, numThreads,
                                  oc::SilentSecType::SemiHonest);
#endif
  }
}

Proto SilentTripleGen::generateBaseOts(u64 partyIdx, coproto::Socket& chl) {
#ifdef LIBOTE_HAS_STATIONARY_SILENT_OT
  (void)partyIdx;
  SetTimePoint("TripleGen::generateBaseOts begin");
  if (!hasBaseOts()) {
    for (u64 i = 0; i < mImpl->mSenderOT.size(); ++i) {
      co_await(mImpl->mSenderOT[i].genBaseCors(std::nullopt, mImpl->mPrng,
                                               chl, true));
    }
    for (u64 i = 0; i < mImpl->mRecverOT.size(); ++i) {
      co_await(mImpl->mRecverOT[i].genBaseCors(mImpl->mPrng, chl, true));
    }
    mImpl->mHasBase = true;
  }
  SetTimePoint("TripleGen::generateBaseOts end");
#else
  auto rMsg = std::vector<block>{};
  auto sMsg = std::vector<std::array<block, 2>>{};
  auto b = RequiredBase{};

  SetTimePoint("TripleGen::generateBaseOts begin");
  b = requiredBaseOts();

  if (b.mNumSend || b.mRecvChoiceBits.size()) {
    rMsg.resize(b.mRecvChoiceBits.size());
    sMsg.resize(b.mNumSend);
    co_await(generateBase(b, partyIdx, mImpl->mPrng, chl, rMsg, sMsg,
                          nullptr));
    setBaseOts(rMsg, sMsg);
  }
  SetTimePoint("TripleGen::generateBaseOts end");
#endif
}

#ifndef LIBOTE_HAS_STATIONARY_SILENT_OT
RequiredBase SilentTripleGen::requiredBaseOts() {
  auto& base = mImpl->mBase;
  base.mNumSend = 0;
  base.mRecvChoiceBits = {};
  if (!hasBaseOts()) {
    for (u64 i = 0; i < mImpl->mRecverOT.size(); i++) {
      base.mRecvChoiceBits.append(
          mImpl->mRecverOT[i].sampleBaseChoiceBits(mImpl->mPrng));
    }
    for (u64 i = 0; i < mImpl->mSenderOT.size(); i++) {
      base.mNumSend += mImpl->mSenderOT[i].silentBaseOtCount();
    }
  }
  return base;
}

void SilentTripleGen::setBaseOts(span<block> recvOts,
                                 span<std::array<block, 2>> sendOts) {
  for (u64 i = 0; i < mImpl->mSenderOT.size(); i++) {
    const auto base_count = mImpl->mSenderOT[i].silentBaseOtCount();
    mImpl->mSenderOT[i].setSilentBaseOts(sendOts.subspan(0, base_count));
    sendOts = sendOts.subspan(base_count);
  }

  for (u64 i = 0; i < mImpl->mRecverOT.size(); i++) {
    const auto base_count = mImpl->mRecverOT[i].silentBaseOtCount();
    mImpl->mRecverOT[i].setSilentBaseOts(recvOts.subspan(0, base_count));
    recvOts = recvOts.subspan(base_count);
  }

  mImpl->mHasBase = true;
}
#endif

#ifndef ENABLE_SSE
inline block _mm_shuffle_epi8(const block &a, const block &b) {
  block ret;
  for (u64 i = 0; i < 16; ++i) {
    u8 bb = b.get<u8>()[i];
    if (bb & 128) {
      ret.set<u8>(i, 0);
    } else {
      u8 idx = bb & 15;
      ret.set<u8>(i, idx);
    }
  }

  return ret;
}

inline block _mm_slli_epi16(const block &a, int imm) {
  block ret;
  for (u64 i = 0; i < 8; ++i) {
    ret.set<u16>(i, a.get<u16>(i) << imm);
  }

  return ret;
}

inline int _mm_movemask_epi8(const block &a) {
  int ret = 0;
  for (u64 i = 0; i < 16; ++i) {
    ret |= int(a.get<u8>()[i] >> 7) << i;
  }
  return ret;
}
#endif

Proto SilentTripleGen::expand(coproto::Socket &chl) {
  auto aIter16 = (u16 *)nullptr;
  auto bIter16 = (u16 *)nullptr;
  [[maybe_unused]] auto aIter = oc::BitIterator{};
  [[maybe_unused]] auto bIter = oc::BitIterator{};
  auto j = u64{};
  auto sendMsg = std::vector<std::array<block, 2>>{};
  auto recvMsg = std::vector<block>{};
  auto recvOtChoiceBits = oc::BitVector{};
  auto shuffle = std::array<block, 16>{};

  memset(shuffle.data(), 1 << 7, sizeof(*shuffle.data()) * shuffle.size());
  for (u64 i = 0; i < 16; ++i) {
    shuffle[i].set<u8>(i, 0);
  }

  SetTimePoint("SilentTripleGen::expand begin");
  if (mImpl->mSenderOT.size()) {
    mImpl->mAVec.resize(mImpl->mN / 128);
    mImpl->mBVec.resize(mImpl->mN / 128);
    mImpl->mMult = mImpl->mAVec;
    mImpl->mAdd = mImpl->mBVec;

    aIter16 = (u16 *)mImpl->mAVec.data();
    bIter16 = (u16 *)mImpl->mBVec.data();
    aIter = oc::BitIterator((u8 *)mImpl->mAVec.data(), 0);
    bIter = oc::BitIterator((u8 *)mImpl->mBVec.data(), 0);

    assert(mImpl->mNumPer % 16 == 0);
    sendMsg.resize(mImpl->mNumPer);
    for (j = 0; j < mImpl->mNumBatchs; ++j) {
      auto& sender = mImpl->mSenderOT[mImpl->mUseStationary ? 0 : j];
      co_await(sender.silentSend(sendMsg, mImpl->mPrng, chl));

      for (u64 i = 0; i < sendMsg.size(); i += 16) {
        block a00 = _mm_shuffle_epi8(sendMsg[i + 0][0], shuffle[0]);
        block a01 = _mm_shuffle_epi8(sendMsg[i + 1][0], shuffle[1]);
        block a02 = _mm_shuffle_epi8(sendMsg[i + 2][0], shuffle[2]);
        block a03 = _mm_shuffle_epi8(sendMsg[i + 3][0], shuffle[3]);
        block a04 = _mm_shuffle_epi8(sendMsg[i + 4][0], shuffle[4]);
        block a05 = _mm_shuffle_epi8(sendMsg[i + 5][0], shuffle[5]);
        block a06 = _mm_shuffle_epi8(sendMsg[i + 6][0], shuffle[6]);
        block a07 = _mm_shuffle_epi8(sendMsg[i + 7][0], shuffle[7]);
        block a08 = _mm_shuffle_epi8(sendMsg[i + 8][0], shuffle[8]);
        block a09 = _mm_shuffle_epi8(sendMsg[i + 9][0], shuffle[9]);
        block a10 = _mm_shuffle_epi8(sendMsg[i + 10][0], shuffle[10]);
        block a11 = _mm_shuffle_epi8(sendMsg[i + 11][0], shuffle[11]);
        block a12 = _mm_shuffle_epi8(sendMsg[i + 12][0], shuffle[12]);
        block a13 = _mm_shuffle_epi8(sendMsg[i + 13][0], shuffle[13]);
        block a14 = _mm_shuffle_epi8(sendMsg[i + 14][0], shuffle[14]);
        block a15 = _mm_shuffle_epi8(sendMsg[i + 15][0], shuffle[15]);

        block b00 = _mm_shuffle_epi8(sendMsg[i + 0][1], shuffle[0]);
        block b01 = _mm_shuffle_epi8(sendMsg[i + 1][1], shuffle[1]);
        block b02 = _mm_shuffle_epi8(sendMsg[i + 2][1], shuffle[2]);
        block b03 = _mm_shuffle_epi8(sendMsg[i + 3][1], shuffle[3]);
        block b04 = _mm_shuffle_epi8(sendMsg[i + 4][1], shuffle[4]);
        block b05 = _mm_shuffle_epi8(sendMsg[i + 5][1], shuffle[5]);
        block b06 = _mm_shuffle_epi8(sendMsg[i + 6][1], shuffle[6]);
        block b07 = _mm_shuffle_epi8(sendMsg[i + 7][1], shuffle[7]);
        block b08 = _mm_shuffle_epi8(sendMsg[i + 8][1], shuffle[8]);
        block b09 = _mm_shuffle_epi8(sendMsg[i + 9][1], shuffle[9]);
        block b10 = _mm_shuffle_epi8(sendMsg[i + 10][1], shuffle[10]);
        block b11 = _mm_shuffle_epi8(sendMsg[i + 11][1], shuffle[11]);
        block b12 = _mm_shuffle_epi8(sendMsg[i + 12][1], shuffle[12]);
        block b13 = _mm_shuffle_epi8(sendMsg[i + 13][1], shuffle[13]);
        block b14 = _mm_shuffle_epi8(sendMsg[i + 14][1], shuffle[14]);
        block b15 = _mm_shuffle_epi8(sendMsg[i + 15][1], shuffle[15]);

        a00 = a00 ^ a08;
        a01 = a01 ^ a09;
        a02 = a02 ^ a10;
        a03 = a03 ^ a11;
        a04 = a04 ^ a12;
        a05 = a05 ^ a13;
        a06 = a06 ^ a14;
        a07 = a07 ^ a15;

        b00 = b00 ^ b08;
        b01 = b01 ^ b09;
        b02 = b02 ^ b10;
        b03 = b03 ^ b11;
        b04 = b04 ^ b12;
        b05 = b05 ^ b13;
        b06 = b06 ^ b14;
        b07 = b07 ^ b15;

        a00 = a00 ^ a04;
        a01 = a01 ^ a05;
        a02 = a02 ^ a06;
        a03 = a03 ^ a07;

        b00 = b00 ^ b04;
        b01 = b01 ^ b05;
        b02 = b02 ^ b06;
        b03 = b03 ^ b07;

        a00 = a00 ^ a02;
        a01 = a01 ^ a03;

        b00 = b00 ^ b02;
        b01 = b01 ^ b03;

        a00 = a00 ^ a01;
        b00 = b00 ^ b01;

        a00 = _mm_slli_epi16(a00, 7);
        b00 = _mm_slli_epi16(b00, 7);

        u16 ap = _mm_movemask_epi8(a00);
        u16 bp = _mm_movemask_epi8(b00);

        *aIter16++ = ap ^ bp;
        *bIter16++ = ap;
      }
    }

    sendMsg = {};
  } else {
    mImpl->mDVec.resize(mImpl->mN / 128);
    mImpl->mCBitVec.resize(0);
    mImpl->mCBitVec.reserve(mImpl->mN);
    mImpl->mAdd = mImpl->mDVec;
    recvMsg.resize(mImpl->mNumPer);
    recvOtChoiceBits.resize(mImpl->mNumPer);
    aIter = oc::BitIterator((u8 *)mImpl->mAdd.data(), 0);
    aIter16 = (u16 *)mImpl->mAdd.data();

    for (j = 0; j < mImpl->mNumBatchs; ++j) {
      auto& receiver = mImpl->mRecverOT[mImpl->mUseStationary ? 0 : j];
      co_await(
          receiver.silentReceive(recvOtChoiceBits, recvMsg, mImpl->mPrng, chl));

      mImpl->mCBitVec.append(recvOtChoiceBits);

      for (u64 i = 0; i < recvMsg.size(); i += 16) {
        block a00 = _mm_shuffle_epi8(recvMsg[i + 0], shuffle[0]);
        block a01 = _mm_shuffle_epi8(recvMsg[i + 1], shuffle[1]);
        block a02 = _mm_shuffle_epi8(recvMsg[i + 2], shuffle[2]);
        block a03 = _mm_shuffle_epi8(recvMsg[i + 3], shuffle[3]);
        block a04 = _mm_shuffle_epi8(recvMsg[i + 4], shuffle[4]);
        block a05 = _mm_shuffle_epi8(recvMsg[i + 5], shuffle[5]);
        block a06 = _mm_shuffle_epi8(recvMsg[i + 6], shuffle[6]);
        block a07 = _mm_shuffle_epi8(recvMsg[i + 7], shuffle[7]);
        block a08 = _mm_shuffle_epi8(recvMsg[i + 8], shuffle[8]);
        block a09 = _mm_shuffle_epi8(recvMsg[i + 9], shuffle[9]);
        block a10 = _mm_shuffle_epi8(recvMsg[i + 10], shuffle[10]);
        block a11 = _mm_shuffle_epi8(recvMsg[i + 11], shuffle[11]);
        block a12 = _mm_shuffle_epi8(recvMsg[i + 12], shuffle[12]);
        block a13 = _mm_shuffle_epi8(recvMsg[i + 13], shuffle[13]);
        block a14 = _mm_shuffle_epi8(recvMsg[i + 14], shuffle[14]);
        block a15 = _mm_shuffle_epi8(recvMsg[i + 15], shuffle[15]);

        a00 = a00 ^ a08;
        a01 = a01 ^ a09;
        a02 = a02 ^ a10;
        a03 = a03 ^ a11;
        a04 = a04 ^ a12;
        a05 = a05 ^ a13;
        a06 = a06 ^ a14;
        a07 = a07 ^ a15;

        a00 = a00 ^ a04;
        a01 = a01 ^ a05;
        a02 = a02 ^ a06;
        a03 = a03 ^ a07;

        a00 = a00 ^ a02;
        a01 = a01 ^ a03;

        a00 = a00 ^ a01;

        a00 = _mm_slli_epi16(a00, 7);

        u16 ap = _mm_movemask_epi8(a00);

        *aIter16++ = ap;
      }
    }
    mImpl->mMult =
        span<block>((block *)mImpl->mCBitVec.data(), mImpl->mAdd.size());
  }

  mImpl->mHasBase = false;
  SetTimePoint("SilentTripleGen::expand end");
}

#ifndef LIBOTE_HAS_STATIONARY_SILENT_OT
Proto generateBase(RequiredBase b, u64 partyIdx, oc::PRNG& prng,
                   coproto::Socket& chl, span<block> recvMsgP,
                   span<std::array<block, 2>> sendMsgP, oc::Timer* timer) {
  if (b.mNumSend != sendMsgP.size() ||
      b.mRecvChoiceBits.size() != recvMsgP.size()) {
    throw RTE_LOC;
  }

  if (partyIdx) {
    auto base = oc::DefaultBaseOT{};
    auto msg = std::vector<std::array<block, 2>>(128);

    co_await(base.send(msg, prng, chl));
    if (timer) {
      timer->setTimePoint("generateBase base");
    }

    co_await(extend(b, msg, prng, chl, recvMsgP, sendMsgP));

    if (timer) {
      timer->setTimePoint("generateBase ext");
    }
  } else {
    auto base = oc::DefaultBaseOT{};
    auto msg = std::vector<block>(128);
    auto bv = oc::BitVector(128);

    bv.randomize(prng);

    co_await(base.receive(bv, msg, prng, chl));
    if (timer) {
      timer->setTimePoint("generateBase base");
    }

    co_await(extend(b, bv, msg, prng, chl, recvMsgP, sendMsgP));

    if (timer) {
      timer->setTimePoint("generateBase ext");
    }
  }
}

Proto extend(RequiredBase b, span<std::array<block, 2>> baseMsg,
             oc::PRNG& prng, coproto::Socket& chl, span<block> recvMsgP,
             span<std::array<block, 2>> sendMsgP) {
  auto recvMsg = std::vector<block>{};
  auto sendMsg = std::vector<std::array<block, 2>>{};
  auto sendBaseChoice = oc::BitVector{};
  auto sendBaseMsg = std::vector<block>{};
  auto recvOT = oc::IknpOtExtReceiver{};
  auto sendOT = oc::IknpOtExtSender{};

  if (recvMsgP.size() != b.mRecvChoiceBits.size() ||
      sendMsgP.size() != b.mNumSend) {
    throw RTE_LOC;
  }

  if (b.mNumSend) {
    sendBaseChoice.resize(128);
    sendBaseMsg.resize(128);
    sendBaseChoice.randomize(prng);
    b.mRecvChoiceBits.append(sendBaseChoice);
  }

  recvMsg.resize(b.mRecvChoiceBits.size());
  sendMsg.resize(b.mNumSend);

  if (recvMsg.size()) {
    recvOT.setBaseOts(baseMsg);
    co_await(recvOT.receive(b.mRecvChoiceBits, recvMsg, prng, chl));

    if (sendBaseChoice.size()) {
      std::copy(recvMsg.end() - 128, recvMsg.end(), sendBaseMsg.begin());
      b.mRecvChoiceBits.resize(b.mRecvChoiceBits.size() - 128);
      recvMsg.resize(recvMsg.size() - 128);
    }
  }

  if (b.mNumSend) {
    if (sendBaseMsg.size()) {
      sendOT.setBaseOts(sendBaseMsg, sendBaseChoice);
    } else {
      co_await(sendOT.genBaseOts(prng, chl));
    }

    co_await(sendOT.send(sendMsg, prng, chl));
  }

  std::copy(recvMsg.begin(), recvMsg.end(), recvMsgP.begin());
  std::copy(sendMsg.begin(), sendMsg.end(), sendMsgP.begin());
}

Proto extend(RequiredBase b, oc::BitVector baseChoice, span<block> baseMsg,
             oc::PRNG& prng, coproto::Socket& chl, span<block> recvMsgP,
             span<std::array<block, 2>> sendMsgP) {
  auto recvMsg = std::vector<block>{};
  auto sendMsg = std::vector<std::array<block, 2>>{};
  auto recvBaseMsg = std::vector<std::array<block, 2>>{};
  auto recvOT = oc::IknpOtExtReceiver{};
  auto sendOT = oc::IknpOtExtSender{};

  if (recvMsgP.size() != b.mRecvChoiceBits.size() ||
      sendMsgP.size() != b.mNumSend) {
    throw RTE_LOC;
  }

  if (b.mRecvChoiceBits.size()) {
    recvBaseMsg.resize(128);
  }

  recvMsg.resize(b.mRecvChoiceBits.size());
  sendMsg.resize(b.mNumSend + recvBaseMsg.size());

  if (sendMsg.size()) {
    sendOT.setBaseOts(baseMsg, baseChoice);
    co_await(sendOT.send(sendMsg, prng, chl));

    if (recvBaseMsg.size()) {
      std::copy(sendMsg.end() - 128, sendMsg.end(), recvBaseMsg.begin());
      sendMsg.resize(sendMsg.size() - 128);
    }
  }

  if (b.mRecvChoiceBits.size()) {
    recvOT.setBaseOts(recvBaseMsg);

    co_await(recvOT.receive(b.mRecvChoiceBits, recvMsg, prng, chl));
  }

  std::copy(recvMsg.begin(), recvMsg.end(), recvMsgP.begin());
  std::copy(sendMsg.begin(), sendMsg.end(), sendMsgP.begin());
}
#endif

} // namespace volePSI
