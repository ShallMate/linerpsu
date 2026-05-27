#pragma once

#include <cstdlib>
#include <iostream>
#include <string>

namespace linerpsu::stage_timing {

inline bool Enabled() {
  static const bool enabled = [] {
    const char* env = std::getenv("PSU_STAGE_TIMING");
    if (env == nullptr) {
      return false;
    }
    const std::string value(env);
    return value == "1" || value == "true" || value == "TRUE" ||
           value == "on" || value == "ON";
  }();
  return enabled;
}

inline void Print(const char* name, double seconds) {
  if (!Enabled()) {
    return;
  }
  std::cerr << "[stage] " << name << ": " << seconds << " seconds"
            << std::endl;
}

}  // namespace linerpsu::stage_timing
