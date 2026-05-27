
#include <sys/types.h>

#include <cstddef>
#include <vector>

#include "coproto/Socket/Socket.h"
#include "yacl/base/int128.h"

namespace eqote {

using namespace std;

vector<uint128_t> EQOTERecv(coproto::Socket& sock, const std::vector<bool>& eqr);

void EQOTESend(coproto::Socket& sock, const std::vector<bool>& eqs,
               const std::vector<uint128_t>& elems);

}  // namespace eqote
