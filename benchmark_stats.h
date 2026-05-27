#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

#include "examples/linerpsu/local_comm_stats.h"
#include "coproto/Socket/Socket.h"

namespace linerpsu::bench {

struct TrafficStats {
  std::array<uint64_t, 2> sent = {0, 0};
  std::array<uint64_t, 2> recv = {0, 0};
};

inline double BytesToMB(uint64_t bytes) {
  return static_cast<double>(bytes) / (1024.0 * 1024.0);
}

inline uint64_t TotalSentBytes(const TrafficStats& stats) {
  return stats.sent[0] + stats.sent[1];
}

inline TrafficStats AddTraffic(const TrafficStats& a, const TrafficStats& b) {
  TrafficStats out;
  for (size_t i = 0; i < 2; ++i) {
    out.sent[i] = a.sent[i] + b.sent[i];
    out.recv[i] = a.recv[i] + b.recv[i];
  }
  return out;
}

inline TrafficStats FromPeqtComm(const psu::local_comm_stats::CommStats& stats) {
  TrafficStats out;
  out.sent = stats.sent;
  out.recv = stats.recv;
  return out;
}

inline TrafficStats FromParty0Socket(uint64_t sent, uint64_t recv) {
  TrafficStats out;
  out.sent[0] = sent;
  out.recv[0] = recv;
  out.sent[1] = recv;
  out.recv[1] = sent;
  return out;
}

inline TrafficStats TakeSocketSnapshot(coproto::Socket& sender_sock,
                                       coproto::Socket& receiver_sock) {
  TrafficStats out;
  out.sent[0] = static_cast<uint64_t>(sender_sock.bytesSent());
  out.recv[0] = static_cast<uint64_t>(sender_sock.bytesReceived());
  out.sent[1] = static_cast<uint64_t>(receiver_sock.bytesSent());
  out.recv[1] = static_cast<uint64_t>(receiver_sock.bytesReceived());
  return out;
}

inline TrafficStats DiffTraffic(const TrafficStats& begin,
                                const TrafficStats& end) {
  TrafficStats out;
  for (size_t i = 0; i < 2; ++i) {
    out.sent[i] = end.sent[i] - begin.sent[i];
    out.recv[i] = end.recv[i] - begin.recv[i];
  }
  return out;
}

inline void PrintTraffic(const std::string& label, const TrafficStats& stats) {
  std::cout << label << " sender sent: " << BytesToMB(stats.sent[0]) << " MB"
            << std::endl;
  std::cout << label << " sender received: " << BytesToMB(stats.recv[0])
            << " MB" << std::endl;
  std::cout << label << " receiver sent: " << BytesToMB(stats.sent[1])
            << " MB" << std::endl;
  std::cout << label << " receiver received: " << BytesToMB(stats.recv[1])
            << " MB" << std::endl;
  std::cout << label << " total communication: "
            << BytesToMB(TotalSentBytes(stats)) << " MB" << std::endl;
}

}  // namespace linerpsu::bench
