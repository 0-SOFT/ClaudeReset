// The exact leading dispatch block, extracted from the hash-verified service.
// No installed service, token or kernel acceptance is claimed by this fixture.
#include <cstdio>
#include <cstdint>
typedef uint32_t ULONG;
#include "ManagedMessageIds.h"
#define STATUS_ACCESS_DENIED 0xC0000022u
#define SHORT_REPLY(status) status
static uint32_t Probe(MSG_HEADER *msg) {
#include "ManagedMutationUnderTest.inc"
    return 0;
}
int main() {
    unsigned blocked=0;
    for (uint32_t id=0;id<65536;id++) {
        // Independent numeric protocol expectations, not the switch's symbols.
        bool mutation=id==0x1806 || id==0x1807 || id==0x1808 || id==0x1811 ||
                      id==0x1812 || id==0x1813 || id==0x1814 || id==0x18D1;
        MSG_HEADER message={};message.msgid=id;
        uint32_t result=Probe(&message);
        if (result!=(mutation?STATUS_ACCESS_DENIED:0u)) {
            std::fprintf(stderr,"check failed: mutation dispatch %x\n",id);
            return 1;
        }
        if (mutation)blocked++;
    }
    std::printf("{\"managed_mutation_ids_checked\":65536,\"managed_mutations_denied\":%u}\n",blocked);
    return 0;
}
