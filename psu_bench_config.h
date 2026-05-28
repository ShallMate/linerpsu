#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "yacl/base/exception.h"

namespace linerpsu::bench_config {

inline uint64_t EnvU64(const char* name, uint64_t default_value) {
  const char* env = std::getenv(name);
  if (env == nullptr || *env == '\0') {
    return default_value;
  }
  char* end = nullptr;
  const auto parsed = std::strtoull(env, &end, 10);
  YACL_ENFORCE(end != env && *end == '\0', "invalid integer env {}={}",
               name, env);
  return parsed;
}

inline bool EnvFlag(const char* name, bool default_value = false) {
  const char* env = std::getenv(name);
  if (env == nullptr || *env == '\0') {
    return default_value;
  }
  const std::string value(env);
  return value != "0" && value != "false" && value != "FALSE" &&
         value != "off" && value != "OFF";
}

enum class OkvsBackend {
  kOkvs,
  kBandOkvs,
};

inline OkvsBackend ParseOkvsBackend() {
  const char* env = std::getenv("LINERPSU_OKVS_BACKEND");
  if (env == nullptr || *env == '\0') {
    return OkvsBackend::kOkvs;
  }
  const std::string value(env);
  if (value == "okvs" || value == "baxos" || value == "OKVS" ||
      value == "BAXOS") {
    return OkvsBackend::kOkvs;
  }
  if (value == "bandokvs" || value == "band_okvs" ||
      value == "BANDOKVS" || value == "BAND_OKVS") {
    return OkvsBackend::kBandOkvs;
  }
  YACL_THROW("invalid LINERPSU_OKVS_BACKEND={}", value);
}

inline const char* OkvsBackendName(OkvsBackend backend) {
  switch (backend) {
    case OkvsBackend::kOkvs:
      return "okvs";
    case OkvsBackend::kBandOkvs:
      return "bandokvs";
  }
  return "unknown";
}

struct PsuOptions {
  uint64_t logn = 20;
  uint64_t ns = 1ULL << 20;
  uint64_t nr = 1ULL << 20;
  uint64_t diff = 10;
  uint32_t recv_timeout_ms = 120000;
  bool result_line = false;
  bool print_comm = false;
  bool hash_opprf_only = false;
  OkvsBackend okvs_backend = OkvsBackend::kOkvs;
};

inline PsuOptions LoadPsuOptions() {
  PsuOptions opts;
  opts.logn = EnvU64("LINERPSU_LOGN", 20);
  YACL_ENFORCE(opts.logn < 63, "LINERPSU_LOGN too large: {}", opts.logn);
  opts.ns = EnvU64("LINERPSU_NS", 1ULL << opts.logn);
  opts.nr = EnvU64("LINERPSU_NR", opts.ns);
  opts.diff = EnvU64("LINERPSU_DIFF", 10);
  opts.recv_timeout_ms =
      static_cast<uint32_t>(EnvU64("LINERPSU_RECV_TIMEOUT_MS", 120000));
  opts.result_line = EnvFlag("LINERPSU_RESULT_LINE", false);
  opts.print_comm = EnvFlag("LINERPSU_PRINT_COMM", false);
  opts.hash_opprf_only = EnvFlag("LINERPSU_HASH_OPPRF_ONLY", false);
  opts.okvs_backend = ParseOkvsBackend();
  YACL_ENFORCE(opts.ns > 0 && opts.nr > 0, "party sizes must be positive");
  YACL_ENFORCE(opts.diff < std::min(opts.ns, opts.nr),
               "diff must be smaller than both party sizes");
  return opts;
}

}  // namespace linerpsu::bench_config
