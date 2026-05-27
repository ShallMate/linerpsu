#pragma once

#include <cstdint>

#include "coproto/Socket/Socket.h"
#include "coproto/coproto.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace linerpsu::own_opprf {

using block = oc::block;
using PRNG = oc::PRNG;
using Proto = coproto::task<void>;

class Sender : public oc::TimerAdapter {
 public:
  Proto GenerateMasks(oc::span<const block> keys, oc::span<block> masks,
                      PRNG& prng, coproto::Socket& chl,
                      uint64_t num_threads = 1);

  Proto Send(oc::span<const block> keys, oc::span<const block> values,
             PRNG& prng, coproto::Socket& chl, uint64_t num_threads = 1);

 private:
  uint64_t fixed_bin_size_ = 0;
  uint64_t ssp_ = 40;
};

class Receiver : public oc::TimerAdapter {
 public:
  Proto GenerateMasks(oc::span<const block> keys, oc::span<block> masks,
                      PRNG& prng, coproto::Socket& chl,
                      uint64_t num_threads = 1);

  Proto Receive(uint64_t sender_size, oc::span<const block> keys,
                oc::span<block> outputs, PRNG& prng, coproto::Socket& chl,
                uint64_t num_threads = 1);

 private:
  uint64_t fixed_bin_size_ = 0;
  uint64_t ssp_ = 40;
};

}  // namespace linerpsu::own_opprf
