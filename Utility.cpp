#include "Utility.h"

#include <map>
#include <string>

std::map<int, std::string> StHelpers::indexes = {
    {0, "UNDEF"},
    {0xff00, "LOPROC"},
    {0xff1f, "HIPROC"},
    {0xff20, "LIVEPATCH"},
    {0xfff1, "ABS"},
    {0xfff2, "COMMON"},
    {0xffff, "HIRESERVE"}
};
std::map<int, std::string> StHelpers::types = {
    {0, "NOTYPE"},
    {1, "OBJECT"},
    {2, "FUNC"},
    {3, "SECTION"},
    {4, "FILE"},
    {5, "COMMON"},
    {6, "TLS"}
};
std::map<int, std::string> StHelpers::visibilities = {
    {0, "DEFAULT"},
    {1, "INTERNAL"},
    {2, "HIDDEN"},
    {3, "PROTECTED"},
    {4, "EXPORTED"},
    {5, "SINGLETON"},
    {6, "ELIMINATE"}
};

std::map<int, std::string> StHelpers::binds = {
    {0, "LOCAL"},
    {1, "GLOBAL"},
    {2, "WEAK"}
};
