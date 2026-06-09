#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class TlsParseResult {
    NeedMore,
    Invalid,
    SNINotFound,
    SNIFound
};

TlsParseResult parseClientHelloSni(
    const std::vector<uint8_t>& stream,
    std::string& serverName
);
