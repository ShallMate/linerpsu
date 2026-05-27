#pragma once

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "coproto/Socket/AsioSocket.h"
#include "coproto/coproto.h"
#include "yacl/base/exception.h"

namespace linerpsu::socket_io {

struct ParsedAddress {
  std::string host;
  uint16_t port = 0;
};

struct SocketStats {
  uint64_t sent = 0;
  uint64_t recv = 0;
};

inline ParsedAddress ParseAddress(const std::string& address) {
  const auto pos = address.rfind(':');
  YACL_ENFORCE(pos != std::string::npos,
               "socket address must be host:port, got={}", address);
  ParsedAddress parsed;
  parsed.host = address.substr(0, pos);
  const auto port_str = address.substr(pos + 1);
  int port = 0;
  try {
    port = std::stoi(port_str);
  } catch (const std::exception&) {
    YACL_THROW("invalid socket port in address: {}", address);
  }
  YACL_ENFORCE(port > 0 && port <= 65535, "invalid socket port={}", port);
  parsed.port = static_cast<uint16_t>(port);
  return parsed;
}

inline std::string PsuBaseAddress() {
  if (const char* env = std::getenv("LINERPSU_SOCKET_ADDRESS")) {
    return std::string(env);
  }
  return "127.0.0.1:13205";
}

inline std::string OffsetAddress(const std::string& base, size_t offset) {
  auto parsed = ParseAddress(base);
  const uint32_t port =
      static_cast<uint32_t>(parsed.port) + static_cast<uint32_t>(offset);
  YACL_ENFORCE(port <= 65535, "socket port overflow, base={}, offset={}",
               base, offset);
  std::ostringstream oss;
  oss << parsed.host << ":" << port;
  return oss.str();
}

inline coproto::AsioSocket ConnectSocket(const std::string& address,
                                         bool is_listener) {
  if (is_listener) {
    return coproto::asioConnect(address, true);
  }

  constexpr int kMaxRetry = 200;
  for (int attempt = 0; attempt < kMaxRetry; ++attempt) {
    try {
      return coproto::asioConnect(address, false);
    } catch (const std::exception&) {
      if (attempt + 1 == kMaxRetry) {
        throw;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  YACL_THROW("failed to connect socket: {}", address);
}

inline std::pair<coproto::AsioSocket, coproto::AsioSocket> ConnectSocketPair(
    const std::string& address) {
  auto listener = std::async(std::launch::async,
                             [&] { return ConnectSocket(address, true); });
  auto client = ConnectSocket(address, false);
  return {listener.get(), std::move(client)};
}

inline SocketStats Snapshot(coproto::Socket& sock) {
  return {static_cast<uint64_t>(sock.bytesSent()),
          static_cast<uint64_t>(sock.bytesReceived())};
}

inline SocketStats Diff(const SocketStats& begin, const SocketStats& end) {
  return {end.sent - begin.sent, end.recv - begin.recv};
}

inline void Flush(coproto::Socket& sock) { coproto::sync_wait(sock.flush()); }

template <typename T>
inline void SendValue(coproto::Socket& sock, const T& value) {
  coproto::sync_wait(sock.send(coproto::copy(value)));
  Flush(sock);
}

template <typename T>
inline T RecvValue(coproto::Socket& sock) {
  T value{};
  coproto::sync_wait(sock.recv(value));
  return value;
}

template <typename T>
inline void SendVector(coproto::Socket& sock, const std::vector<T>& values) {
  coproto::sync_wait(sock.send(coproto::copy(values)));
  Flush(sock);
}

template <typename T>
inline std::vector<T> RecvVector(coproto::Socket& sock, size_t size) {
  std::vector<T> values(size);
  coproto::sync_wait(sock.recv(values));
  return values;
}

}  // namespace linerpsu::socket_io
