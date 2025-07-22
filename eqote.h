
#include <sys/types.h>
#include <cstddef>

#include <vector>

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"
#include "yacl/link/test_util.h"

namespace eqote {

using namespace yacl::crypto;
using namespace std;

vector<uint128_t> EQOTERecv(const std::shared_ptr<yacl::link::Context>& ctx,const std::vector<bool>& eqr);

void EQOTESend(const std::shared_ptr<yacl::link::Context>& ctx,const std::vector<bool>& eqs,
               const std::vector<uint128_t>& elems);

}