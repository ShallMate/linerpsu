#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"

namespace gmw_eq_vec_u64_prerot {

using Block = yacl::crypto::Block;

// -------------------- stats helpers --------------------
struct StatSnap {
  uint64_t sent = 0;
  uint64_t recv = 0;
};




// -------------------- byte send/recv helpers --------------------
static inline void SendAsyncBytes(const std::shared_ptr<yacl::link::Context>& ctx,
                                  int dst_rank, const std::string& tag,
                                  const void* data, size_t nbytes) {
  ctx->SendAsync(dst_rank, yacl::ByteContainerView(data, nbytes), tag);
}

static inline std::vector<uint8_t> RecvBytes(const std::shared_ptr<yacl::link::Context>& ctx,
                                             int src_rank, const std::string& tag) {
  auto buf = ctx->Recv(src_rank, tag);
  std::vector<uint8_t> out(buf.size());
  if (!out.empty()) {
    std::memcpy(out.data(), buf.data(), buf.size());
  }
  return out;
}

static inline void SendU64(const std::shared_ptr<yacl::link::Context>& ctx,
                           int dst_rank, const std::string& tag, uint64_t v) {
  SendAsyncBytes(ctx, dst_rank, tag, &v, sizeof(uint64_t));
}

static inline uint64_t RecvU64(const std::shared_ptr<yacl::link::Context>& ctx,
                               int src_rank, const std::string& tag) {
  auto bytes = RecvBytes(ctx, src_rank, tag);
  YACL_ENFORCE(bytes.size() == sizeof(uint64_t), "RecvU64 size mismatch");
  uint64_t v = 0;
  std::memcpy(&v, bytes.data(), sizeof(uint64_t));
  return v;
}

static inline uint8_t DecodeBit(const Block& blk) {
  const auto* p = reinterpret_cast<const uint8_t*>(&blk);
  return static_cast<uint8_t>(p[0] & 1);
}

// -------------------- pack/unpack bits (packed bytes) --------------------
static inline uint8_t GetPackedBit(const std::vector<uint8_t>& packed, size_t i) {
  return static_cast<uint8_t>((packed[i >> 3] >> (i & 7)) & 1);
}

static inline void SetPackedBit(std::vector<uint8_t>* packed, size_t i, uint8_t b) {
  if (b & 1) {
    (*packed)[i >> 3] |= static_cast<uint8_t>(1u << (i & 7));
  }
}


struct RotDir {
  bool is_sender = false;
  bool is_receiver = false;

  std::unique_ptr<yacl::crypto::OtSendStore> send;  
  std::unique_ptr<yacl::crypto::OtRecvStore> recv;  
  yacl::dynamic_bitset<> r;                         

  size_t cursor = 0; 
};

static inline uint64_t SplitMix64(uint64_t& x) {
  x += 0x9e3779b97f4a7c15ULL;
  uint64_t z = x;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

static inline yacl::crypto::Block MakeBlock(uint64_t lo, uint64_t hi) {
  yacl::crypto::Block b{};
  std::memcpy(reinterpret_cast<uint8_t*>(&b) + 0, &lo, 8);
  std::memcpy(reinterpret_cast<uint8_t*>(&b) + 8, &hi, 8);
  return b;
}

static inline yacl::crypto::Block DeriveBlock(uint64_t seed, uint64_t idx, uint64_t which) {
  uint64_t x = seed ^ (idx * 0xD2B74407B1CE6E93ULL) ^ (which * 0xCA5A826395121157ULL);
  uint64_t lo = SplitMix64(x);
  uint64_t hi = SplitMix64(x);
  return MakeBlock(lo, hi);
}

static inline uint8_t DeriveBit(uint64_t seed, uint64_t idx) {
  uint64_t x = seed ^ (idx * 0x9E3779B97F4A7C15ULL);
  uint64_t v = SplitMix64(x);
  return static_cast<uint8_t>(v & 1ULL);
}


static constexpr uint64_t kSeedKeys01 = 0x0123456789ABCDEFULL;  // dir01 keys
static constexpr uint64_t kSeedKeys10 = 0xFEDCBA9876543210ULL;  // dir10 keys

static constexpr uint64_t kSeedChoice01 = 0x0F0E0D0C0B0A0908ULL; // dir01 receiver choice
static constexpr uint64_t kSeedChoice10 = 0x8070605040302010ULL; // dir10 receiver choice

static inline void FillFakeSendStore(yacl::crypto::OtSendStore* st,
                                     size_t n, uint64_t seed_keys) {
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      auto k0 = DeriveBlock(seed_keys, static_cast<uint64_t>(i), 0);
      auto k1 = DeriveBlock(seed_keys, static_cast<uint64_t>(i), 1);
      st->SetNormalBlock(i, 0, k0);
      st->SetNormalBlock(i, 1, k1);
    }
  });
}

static inline void FillFakeRecvStore(yacl::crypto::OtRecvStore* rt,
                                     yacl::dynamic_bitset<>* r_bits,
                                     size_t n, uint64_t seed_keys, uint64_t seed_choice) {
  r_bits->resize(n);
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      uint8_t r = DeriveBit(seed_choice, static_cast<uint64_t>(i));
      (*r_bits)[i] = (r != 0);
      auto kc = DeriveBlock(seed_keys, static_cast<uint64_t>(i), static_cast<uint64_t>(r));
      rt->SetBlock(i, kc);
    }
  });
}

static inline void PrecomputeAllRot(int rank, size_t total_ots,
                                    RotDir* dir01, RotDir* dir10) {
  YACL_ENFORCE(total_ots > 0, "total_ots must be > 0");
  if (rank == 0) {
    // dir01: sender
    dir01->is_sender = true;
    {
      auto st = yacl::crypto::OtSendStore(total_ots, yacl::crypto::OtStoreType::Normal);
      FillFakeSendStore(&st, total_ots, kSeedKeys01);
      dir01->send = std::make_unique<yacl::crypto::OtSendStore>(std::move(st));
    }
    dir01->cursor = 0;

    // dir10: receiver
    dir10->is_receiver = true;
    {
      auto rt = yacl::crypto::OtRecvStore(total_ots, yacl::crypto::OtStoreType::Normal);
      FillFakeRecvStore(&rt, &dir10->r, total_ots, kSeedKeys10, kSeedChoice10);
      dir10->recv = std::make_unique<yacl::crypto::OtRecvStore>(std::move(rt));
    }
    dir10->cursor = 0;
  } else {
    // rank1
    // dir01: receiver
    dir01->is_receiver = true;
    {
      auto rt = yacl::crypto::OtRecvStore(total_ots, yacl::crypto::OtStoreType::Normal);
      FillFakeRecvStore(&rt, &dir01->r, total_ots, kSeedKeys01, kSeedChoice01);
      dir01->recv = std::make_unique<yacl::crypto::OtRecvStore>(std::move(rt));
    }
    dir01->cursor = 0;

    // dir10: sender
    dir10->is_sender = true;
    {
      auto st = yacl::crypto::OtSendStore(total_ots, yacl::crypto::OtStoreType::Normal);
      FillFakeSendStore(&st, total_ots, kSeedKeys10);
      dir10->send = std::make_unique<yacl::crypto::OtSendStore>(std::move(st));
    }
    dir10->cursor = 0;
  }
}

static inline void ReceiverSendDelta(const std::shared_ptr<yacl::link::Context>& ctx,
                                     int peer,
                                     const std::string& delta_tag,
                                     const std::vector<uint8_t>& choice_bits,  // c
                                     const RotDir& dir,
                                     size_t base, size_t M) {
  YACL_ENFORCE(dir.is_receiver && dir.recv, "Receiver dir not initialized");
  YACL_ENFORCE(choice_bits.size() == M);

  const size_t nbytes = (M + 7) / 8;
  std::vector<uint8_t> packed_delta(nbytes, 0);
  yacl::parallel_for(0, M, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      uint8_t rbit = static_cast<uint8_t>(dir.r[base + i] ? 1 : 0);
      uint8_t dbit = static_cast<uint8_t>((choice_bits[i] ^ rbit) & 1);
      SetPackedBit(&packed_delta, i, dbit);
    }
  });
  SendAsyncBytes(ctx, peer, delta_tag, packed_delta.data(), packed_delta.size());
}

static inline std::vector<uint8_t> SenderRecvDeltaAndSendCT_Packed(
    const std::shared_ptr<yacl::link::Context>& ctx,
    int peer,
    const std::string& delta_tag,
    const std::string& ct_tag,
    const std::vector<uint8_t>& u_bits,
    RotDir* dir,
    size_t base, size_t M) {
  YACL_ENFORCE(dir->is_sender && dir->send, "Sender dir not initialized");
  YACL_ENFORCE(u_bits.size() == M);

  auto packed_delta = RecvBytes(ctx, peer, delta_tag);
  YACL_ENFORCE(packed_delta.size() == (M + 7) / 8,
               "delta bytes mismatch: got {}, want {}",
               packed_delta.size(), (M + 7) / 8);

  auto rbits = yacl::crypto::SecureRandBits(M);
  std::vector<uint8_t> r_vec(M, 0);

  const size_t ct_bits = 2 * M;
  const size_t ct_nbytes = (ct_bits + 7) / 8;
  std::vector<uint8_t> packed_ct(ct_nbytes, 0);

  yacl::parallel_for(0, M, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      uint8_t r = static_cast<uint8_t>(rbits[i] ? 1 : 0);
      r_vec[i] = r;

      uint8_t m0 = r;
      uint8_t m1 = static_cast<uint8_t>(r ^ (u_bits[i] & 1));

      uint8_t delta = GetPackedBit(packed_delta, i);
      if (delta != 0u) { std::swap(m0, m1); }

      const size_t idx = base + i;
      Block k0 = dir->send->GetBlock(idx, 0);
      Block k1 = dir->send->GetBlock(idx, 1);

      // 1-bit pad from ROT keys (demo: LSB of block)
      uint8_t pad0 = DecodeBit(k0);
      uint8_t pad1 = DecodeBit(k1);

      uint8_t c0 = uint8_t((m0 ^ pad0) & 1);
      uint8_t c1 = uint8_t((m1 ^ pad1) & 1);

      SetPackedBit(&packed_ct, 2 * i + 0, c0);
      SetPackedBit(&packed_ct, 2 * i + 1, c1);
    }
  });

  SendAsyncBytes(ctx, peer, ct_tag, packed_ct.data(), packed_ct.size());
  return r_vec;
}

// -------------------- receiver receives packed CT and decodes --------------------
static inline std::vector<uint8_t> ReceiverRecvCTAndDecode_Packed(
    const std::shared_ptr<yacl::link::Context>& ctx,
    int peer,
    const std::string& ct_tag,
    RotDir* dir,
    size_t base, size_t M) {
  YACL_ENFORCE(dir->is_receiver && dir->recv, "Receiver dir not initialized");

  const size_t ct_bits = 2 * M;
  const size_t ct_nbytes = (ct_bits + 7) / 8;

  auto packed_ct = RecvBytes(ctx, peer, ct_tag);
  YACL_ENFORCE(packed_ct.size() == ct_nbytes,
               "ct bytes mismatch: got {}, want {}",
               packed_ct.size(), ct_nbytes);

  std::vector<uint8_t> out(M, 0);
  yacl::parallel_for(0, M, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      uint8_t rbit = static_cast<uint8_t>(dir->r[base + i] ? 1 : 0);
      Block kc = dir->recv->GetBlock(base + i);

      // 1-bit pad from ROT key (demo: LSB of block)
      uint8_t pad = DecodeBit(kc);
      uint8_t c = GetPackedBit(packed_ct, 2 * i + rbit);
      out[i] = static_cast<uint8_t>((c ^ pad) & 1);
    }
  });
  return out;
}


static inline std::vector<uint8_t> AndBatchPreRot(const std::shared_ptr<yacl::link::Context>& ctx,
                                                  const std::vector<uint8_t>& x_bits,
                                                  const std::vector<uint8_t>& y_bits,
                                                  int rank,
                                                  RotDir* dir01,  // 0->1
                                                  RotDir* dir10,  // 1->0
                                                  const std::string& layer_tag) {
  YACL_ENFORCE(x_bits.size() == y_bits.size());
  const size_t M = x_bits.size();
  if (M == 0) return {};
  int peer = 1 - rank;

  std::vector<uint8_t> local(M);
  for (size_t i = 0; i < M; ++i) local[i] = static_cast<uint8_t>((x_bits[i] & y_bits[i]) & 1);

  const size_t base01 = dir01->cursor;
  const size_t base10 = dir10->cursor;

  const std::string d01_tag = layer_tag + "_delta01";
  const std::string c01_tag = layer_tag + "_ct01";
  const std::string d10_tag = layer_tag + "_delta10";
  const std::string c10_tag = layer_tag + "_ct10";

  // A) receiver sends delta
  if (rank == 0) {
    ReceiverSendDelta(ctx, peer, d10_tag, y_bits, *dir10, base10, M);
  } else {
    ReceiverSendDelta(ctx, peer, d01_tag, y_bits, *dir01, base01, M);
  }

  // B) sender receives delta and sends packed ct
  std::vector<uint8_t> r01(M, 0);
  std::vector<uint8_t> r10(M, 0);
  if (rank == 0) {
    r01 = SenderRecvDeltaAndSendCT_Packed(ctx, peer, d01_tag, c01_tag, x_bits, dir01, base01, M);
  } else {
    r10 = SenderRecvDeltaAndSendCT_Packed(ctx, peer, d10_tag, c10_tag, x_bits, dir10, base10, M);
  }

  // C) receiver receives packed ct and decodes
  std::vector<uint8_t> u01(M, 0);
  std::vector<uint8_t> u10(M, 0);
  if (rank == 0) {
    u10 = ReceiverRecvCTAndDecode_Packed(ctx, peer, c10_tag, dir10, base10, M);
  } else {
    u01 = ReceiverRecvCTAndDecode_Packed(ctx, peer, c01_tag, dir01, base01, M);
  }

  dir01->cursor += M;
  dir10->cursor += M;

  std::vector<uint8_t> z(M, 0);
  if (rank == 0) {
    for (size_t i = 0; i < M; ++i) {
      z[i] = static_cast<uint8_t>(local[i] ^ (r01[i] & 1) ^ (u10[i] & 1));
    }
  } else {
    for (size_t i = 0; i < M; ++i) {
      z[i] = static_cast<uint8_t>(local[i] ^ (u01[i] & 1) ^ (r10[i] & 1));
    }
  }
  return z;
}

// -------------------- main protocol (treat inputs as shares of z=x^y; just run isZero(z)) --------------------
static inline std::vector<bool> EqU64Vec2PC_PreRot(const std::shared_ptr<yacl::link::Context>& ctx,
                                                      int rank,
                                                      const std::vector<uint64_t>& my_vec,
                                                      const std::string& tag_prefix) {
  //const char* who = (rank == 0) ? "P0" : "P1";
  int peer = 1 - rank;

  // Exchange size (tiny)
  const uint64_t my_n = static_cast<uint64_t>(my_vec.size());
  if (rank == 0) {
    SendU64(ctx, peer, tag_prefix + "_n01", my_n);
    uint64_t other_n = RecvU64(ctx, peer, tag_prefix + "_n10");
    YACL_ENFORCE(other_n == my_n, "Size mismatch: n0={} n1={}", my_n, other_n);
  } else {
    SendU64(ctx, peer, tag_prefix + "_n10", my_n);
    uint64_t other_n = RecvU64(ctx, peer, tag_prefix + "_n01");
    YACL_ENFORCE(other_n == my_n, "Size mismatch: n0={} n1={}", other_n, my_n);
  }

  const size_t n = my_vec.size();
  if (n == 0) return {};

  //auto t0 = TakeSnap(ctx);

  // Precompute ALL ROT once
  const size_t total_ands = 63ULL * n;
  const size_t total_ots_per_dir = total_ands;

  RotDir dir01;
  RotDir dir10;
  PrecomputeAllRot(rank, total_ots_per_dir, &dir01, &dir10);

  //auto t1 = TakeSnap(ctx);
  //PrintDelta(who, "PHASE PrecomputeAllRot (overall)", t0, t1);

  // Key change:
  // Treat my_vec as my XOR-share of z = x XOR y:
  //   rank0 holds z0 = x, rank1 holds z1 = y.
  // Then reconstruct z = z0 XOR z1 = x XOR y, and isZero(z) ⇔ x==y.
  int width = 64;
  std::vector<uint8_t> cur(n * static_cast<size_t>(width));
  for (size_t i = 0; i < n; ++i) {
    uint64_t w = my_vec[i];  // z-share
    for (int k = 0; k < 64; ++k) {
      cur[i * 64ULL + static_cast<size_t>(k)] = static_cast<uint8_t>((w >> k) & 1);
    }
  }

  // OR-reduction on shared bits
  for (int layer = 0; layer < 6; ++layer) {
    const int next_w = width / 2;
    const size_t M = n * static_cast<size_t>(next_w);

    std::vector<uint8_t> x_bits(M);
    std::vector<uint8_t> y_bits(M);
    for (size_t i = 0; i < n; ++i) {
      for (int j = 0; j < next_w; ++j) {
        const size_t gid = i * static_cast<size_t>(next_w) + static_cast<size_t>(j);
        x_bits[gid] = cur[i * static_cast<size_t>(width) + static_cast<size_t>(2 * j + 0)];
        y_bits[gid] = cur[i * static_cast<size_t>(width) + static_cast<size_t>(2 * j + 1)];
      }
    }

    const std::string layer_tag = tag_prefix + "_L" + std::to_string(layer);
    auto and_bits = AndBatchPreRot(ctx, x_bits, y_bits, rank, &dir01, &dir10, layer_tag);

    std::vector<uint8_t> next(n * static_cast<size_t>(next_w));
    for (size_t gid = 0; gid < M; ++gid) {
      // OR = x XOR y XOR (x AND y)
      next[gid] = static_cast<uint8_t>((x_bits[gid] ^ y_bits[gid] ^ and_bits[gid]) & 1);
    }
    cur.swap(next);
    width = next_w;
  }

  //auto t2 = TakeSnap(ctx);
  //PrintDelta(who, "PHASE Online(6 layers)", t1, t2);

  // eq_share = NOT(neq_share) (only rank0 flips)
  std::vector<bool> eq_share(n);
  for (size_t i = 0; i < n; ++i) {
    bool s = static_cast<bool>(cur[i] & 1);  // neq_share
    if (rank == 0) s ^= 1;
    eq_share[i] = s;
  }
  return eq_share;
}

}  

static inline std::vector<bool> Party(const std::shared_ptr<yacl::link::Context>& ctx,
                                  const std::vector<uint64_t>& a_vec) {
  return gmw_eq_vec_u64_prerot::EqU64Vec2PC_PreRot(ctx, ctx->Rank(), a_vec, "GMW_EQ_PREROT");
}