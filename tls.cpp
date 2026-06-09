#include "tls.h"

#include <cstddef>
#include <cstdint>
#include <vector>

using namespace std;

static uint32_t readBigEndian(const uint8_t* p, size_t size) {
    uint32_t value = 0;

    for (size_t i = 0; i < size; i++)
        value = (value << 8) | p[i];

    return value;
}

TlsParseResult parseClientHelloSni(const vector<uint8_t>& stream, string& serverName) {
    serverName.clear();

    vector<uint8_t> handshake;
    size_t recordOffset = 0;

    while (true) {
        if (stream.size() - recordOffset < 5)
            return TlsParseResult::NeedMore;

        const uint8_t contentType = stream[recordOffset];
        const uint8_t versionMajor = stream[recordOffset + 1];
        const uint16_t recordLength = readBigEndian(&stream[recordOffset + 3], 2);

        if (contentType != 22 || versionMajor != 3 || recordLength > 18432)
            return TlsParseResult::Invalid;

        if (stream.size() - recordOffset < size_t(5 + recordLength))
            return TlsParseResult::NeedMore;

        handshake.insert(
            handshake.end(),
            stream.begin() + recordOffset + 5,
            stream.begin() + recordOffset + 5 + recordLength
        );

        recordOffset += 5 + recordLength;

        if (handshake.size() < 4) {
            if (recordOffset == stream.size())
                return TlsParseResult::NeedMore;
            continue;
        }

        if (handshake[0] != 1)
            return TlsParseResult::Invalid;

        const uint32_t clientHelloLength = readBigEndian(&handshake[1], 3);

        if (clientHelloLength > 1024 * 1024)
            return TlsParseResult::Invalid;

        if (handshake.size() < size_t(4 + clientHelloLength)) {
            if (recordOffset == stream.size())
                return TlsParseResult::NeedMore;
            continue;
        }

        const uint8_t* body = handshake.data() + 4;
        const size_t bodyLength = clientHelloLength;
        size_t offset = 0;

        // legacy_version(2) + random(32)
        if (bodyLength < 34)
            return TlsParseResult::Invalid;
        offset = 34;

        // legacy_session_id
        if (offset + 1 > bodyLength)
            return TlsParseResult::Invalid;
        const uint8_t sessionIdLength = body[offset++];
        if (offset + sessionIdLength > bodyLength)
            return TlsParseResult::Invalid;
        offset += sessionIdLength;

        // cipher_suites
        if (offset + 2 > bodyLength)
            return TlsParseResult::Invalid;
        const uint16_t cipherSuitesLength = readBigEndian(body + offset, 2);
        offset += 2;
        if (cipherSuitesLength == 0 || (cipherSuitesLength & 1) != 0 ||
            offset + cipherSuitesLength > bodyLength)
            return TlsParseResult::Invalid;
        offset += cipherSuitesLength;

        // legacy_compression_methods
        if (offset + 1 > bodyLength)
            return TlsParseResult::Invalid;
        const uint8_t compressionMethodsLength = body[offset++];
        if (compressionMethodsLength == 0 ||
            offset + compressionMethodsLength > bodyLength)
            return TlsParseResult::Invalid;
        offset += compressionMethodsLength;

        // ClientHello without extensions
        if (offset == bodyLength)
            return TlsParseResult::SNINotFound;

        if (offset + 2 > bodyLength)
            return TlsParseResult::Invalid;

        const uint16_t extensionsLength = readBigEndian(body + offset, 2);
        offset += 2;

        if (offset + extensionsLength != bodyLength)
            return TlsParseResult::Invalid;

        const size_t extensionsEnd = offset + extensionsLength;

        while (offset < extensionsEnd) {
            if (offset + 4 > extensionsEnd)
                return TlsParseResult::Invalid;

            const uint16_t extensionType = readBigEndian(body + offset, 2);
            const uint16_t extensionLength = readBigEndian(body + offset + 2, 2);
            offset += 4;

            printf(
                "[EXT] type=%u (0x%04X) length=%u\n",
                extensionType,
                extensionType,
                extensionLength
            );

            if (offset + extensionLength > extensionsEnd)
                return TlsParseResult::Invalid;

            if (extensionType == 0) {
                const size_t extensionEnd = offset + extensionLength;

                printf(
                    "[SNI EXT] offset=%zu extensionLength=%u "
                    "extensionEnd=%zu\n",
                    offset,
                    extensionLength,
                    extensionEnd
                );

                if (extensionLength < 2)
                    return TlsParseResult::Invalid;

                const uint16_t serverNameListLength = readBigEndian(body + offset, 2);
                size_t nameOffset = offset + 2;

                printf(
                    "[SNI LIST] listLength=%u nameOffset=%zu\n",
                    serverNameListLength,
                    nameOffset
                );

                if (nameOffset + serverNameListLength != extensionEnd)
                    return TlsParseResult::Invalid;

                while (nameOffset < extensionEnd) {
                    if (nameOffset + 3 > extensionEnd)
                        return TlsParseResult::Invalid;

                    const uint8_t nameType = body[nameOffset];
                    const uint16_t nameLength = readBigEndian(body + nameOffset + 1, 2);
                    nameOffset += 3;

                    if (nameOffset + nameLength > extensionEnd)
                        return TlsParseResult::Invalid;

                    if (nameType == 0) {
                        if (nameLength == 0)
                            return TlsParseResult::Invalid;

                        serverName.assign(
                            reinterpret_cast<const char*>(body + nameOffset),
                            nameLength
                        );
                        return TlsParseResult::SNIFound;
                    }

                    printf(
                        "[SNI NAME] type=%u length=%u value=\"%.*s\"\n",
                        nameType,
                        nameLength,
                        int(nameLength),
                        reinterpret_cast<const char*>(body + nameOffset)
                    );

                    nameOffset += nameLength;
                }

                return TlsParseResult::SNINotFound;
            }

            offset += extensionLength;
        }

        return TlsParseResult::SNINotFound;
    }
}
