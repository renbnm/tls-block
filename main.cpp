#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "ethhdr.h"
#include "ip.h"
#include "tcp.h"
#include "tls.h"

using namespace std;

struct FlowKey {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;

    bool operator<(const FlowKey& r) const {
        return tie(sip, dip, sport, dport) <
               tie(r.sip, r.dip, r.sport, r.dport);
    }
};

struct FlowState {
    vector<uint8_t> stream;

    // 서버가 다음에 받아야 하는 client -> server 방향의 TCP SEQ
    uint32_t nextSeq = 0;

    // 클라이언트가 다음에 받아야 하는 server -> client 방향의 TCP SEQ
    // 관찰한 client 패킷의 ACK 값을 저장한다.
    uint32_t serverNextSeq = 0;

    chrono::steady_clock::time_point updated;
};

uint16_t checksum(const uint8_t* p, int len) {
    uint32_t sum = 0;

    while (len > 1) {
        sum += (uint16_t(p[0]) << 8) | p[1];
        p += 2;
        len -= 2;
    }

    if (len == 1)
        sum += uint16_t(p[0]) << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return htons(uint16_t(~sum));
}

uint16_t tcpChecksum(const IpHdr* ip, const TcpHdr* tcp, int tcpLength) {
    vector<uint8_t> pseudo(12 + tcpLength, 0);

    memcpy(pseudo.data(), &ip->sip_, 4);
    memcpy(pseudo.data() + 4, &ip->dip_, 4);
    pseudo[9] = IpHdr::TCP;

    const uint16_t length = htons(uint16_t(tcpLength));
    memcpy(pseudo.data() + 10, &length, 2);
    memcpy(pseudo.data() + 12, tcp, tcpLength);

    return checksum(pseudo.data(), int(pseudo.size()));
}

string lowerHost(string host) {
    for (char& ch : host)
        ch = char(tolower(static_cast<unsigned char>(ch)));

    while (!host.empty() && host.back() == '.')
        host.pop_back();

    return host;
}

// host가 domain 자체이거나 domain의 하위 도메인인지 검사한다.
// 예: www.youtube.com은 youtube.com과 일치하지만,
//     notyoutube.com은 youtube.com과 일치하지 않는다.
bool domainMatch(const string& host, const string& domain) {
    if (host == domain)
        return true;

    if (host.size() <= domain.size())
        return false;

    const size_t start = host.size() - domain.size();

    return host[start - 1] == '.' &&
           host.compare(start, domain.size(), domain) == 0;
}

bool matchHost(const string& host, const string& target) {
    // 입력한 도메인 자체와 모든 하위 도메인을 차단한다.
    if (domainMatch(host, target))
        return true;

    // youtube.com 또는 그 하위 도메인을 입력한 경우
    // YouTube 서비스가 실제로 사용하는 별도 도메인도 함께 차단한다.
    if (domainMatch(target, "youtube.com")) {
        static const char* youtubeDomains[] = {
            "youtu.be",
            "youtube-nocookie.com",
            "googlevideo.com",
            "ytimg.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "ggpht.com",
            "googleads.g.doubleclick.net"
        };

        for (const char* domain : youtubeDomains) {
            if (domainMatch(host, domain))
                return true;
        }
    }

    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("syntax : tls-block <interface> <server name>\n");
        printf("sample : tls-block wlan0 naver.com\n");
        return -1;
    }

    char* dev = argv[1];
    const string target = lowerHost(argv[2]);

    if (target.empty()) {
        fprintf(stderr, "server name is empty\n");
        return -1;
    }

    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (sd < 0 || ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("interface mac");
        if (sd >= 0) close(sd);
        return -1;
    }

    close(sd);
    Mac myMac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65535, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return -1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "only Ethernet interfaces are supported\n");
        pcap_close(handle);
        return -1;
    }

    // ClientHello 방향인 client -> server TCP/443 패킷만 캡처한다.
    struct bpf_program filter{};
    if (pcap_compile(
            handle,
            &filter,
            "tcp dst port 443",
            1,
            PCAP_NETMASK_UNKNOWN
        ) == 0) {
        pcap_setfilter(handle, &filter);
        pcap_freecode(&filter);
    }

    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int on = 1;

    if (raw < 0 ||
        setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("raw socket");
        if (raw >= 0) close(raw);
        pcap_close(handle);
        return -1;
    }

    map<FlowKey, FlowState> flows;

    printf("tls-block %s %s\n", dev, target.c_str());

    while (true) {
        struct pcap_pkthdr* hdr = nullptr;
        const u_char* packet = nullptr;

        const int res = pcap_next_ex(handle, &hdr, &packet);

        if (res == 0) continue;
        if (res == -1) {
            fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
            break;
        }
        if (res == -2) break;

        if (hdr->caplen < sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr))
            continue;

        EthHdr* eth = reinterpret_cast<EthHdr*>(const_cast<u_char*>(packet));
        IpHdr* ip = reinterpret_cast<IpHdr*>(
            const_cast<u_char*>(packet) + sizeof(EthHdr)
        );

        if (eth->type() != EthHdr::Ip4 ||
            ip->version() != 4 ||
            ip->p() != IpHdr::TCP ||
            ip->hlen() < IpHdr::MinSize ||
            (ip->off() & 0x3FFF) != 0)
            continue;

        if (hdr->caplen < sizeof(EthHdr) + ip->hlen() + TcpHdr::MinSize ||
            ip->tlen() < ip->hlen() + TcpHdr::MinSize)
            continue;

        TcpHdr* tcp = reinterpret_cast<TcpHdr*>(
            reinterpret_cast<uint8_t*>(ip) + ip->hlen()
        );

        if (tcp->len() < TcpHdr::MinSize ||
            ip->tlen() < ip->hlen() + tcp->len())
            continue;

        const int dataSize = ip->tlen() - ip->hlen() - tcp->len();

        if (dataSize <= 0 ||
            hdr->caplen < sizeof(EthHdr) + ip->tlen())
            continue;

        uint8_t* data = reinterpret_cast<uint8_t*>(tcp) + tcp->len();

        const auto now = chrono::steady_clock::now();
        for (auto it = flows.begin(); it != flows.end();) {
            if (now - it->second.updated > chrono::seconds(30))
                it = flows.erase(it);
            else
                ++it;
        }

        FlowKey key{ip->sip_, ip->dip_, tcp->sport_, tcp->dport_};
        auto it = flows.find(key);

        if (it == flows.end()) {
            // TLS Handshake record: ContentType 0x16, legacy version 0x03xx
            if (dataSize < 2 || data[0] != 0x16 || data[1] != 0x03)
                continue;

            FlowState state;
            state.stream.insert(state.stream.end(), data, data + dataSize);

            // SYN과 FIN도 TCP sequence space를 각각 1씩 소비한다.
            state.nextSeq = tcp->seq() + uint32_t(dataSize);
            if (tcp->syn()) state.nextSeq++;
            if (tcp->fin()) state.nextSeq++;

            state.serverNextSeq = tcp->ack();
            state.updated = now;
            it = flows.emplace(key, move(state)).first;
        } else {
            FlowState& state = it->second;
            const uint32_t seq = tcp->seq();
            const int32_t delta = static_cast<int32_t>(seq - state.nextSeq);

            if (delta == 0) {
                state.stream.insert(state.stream.end(), data, data + dataSize);
                state.nextSeq += uint32_t(dataSize);

                if (tcp->syn()) state.nextSeq++;
                if (tcp->fin()) state.nextSeq++;
            } else if (delta < 0) {
                // 이미 받은 범위와 겹치는 재전송이면 새로운 부분만 추가한다.
                const uint32_t overlap = uint32_t(-delta);

                if (overlap < uint32_t(dataSize)) {
                    state.stream.insert(
                        state.stream.end(),
                        data + overlap,
                        data + dataSize
                    );
                    state.nextSeq += uint32_t(dataSize) - overlap;
                }
            } else {
                // 중간 segment가 빠졌거나 out-of-order인 경우에는
                // 현재 단순 재조립 방식으로 정확히 복원할 수 없다.
                flows.erase(it);
                continue;
            }

            // 현재 client 패킷의 ACK가 클라이언트가 기대하는
            // 다음 server -> client SEQ다.
            state.serverNextSeq = tcp->ack();
            state.updated = now;
        }

        if (it->second.stream.size() > 1024 * 1024) {
            flows.erase(it);
            continue;
        }

        string serverName;
        const TlsParseResult parseResult =
            parseClientHelloSni(it->second.stream, serverName);

        if (parseResult == TlsParseResult::NeedMore)
            continue;

        if (parseResult == TlsParseResult::Invalid ||
            parseResult == TlsParseResult::SNINotFound) {
            flows.erase(it);
            continue;
        }

        const string parsedHost = lowerHost(serverName);

        if (!matchHost(parsedHost, target)) {
            flows.erase(it);
            continue;
        }

        // 지금까지 재조립한 전체 client 데이터를 기준으로 갱신된 SEQ를 사용한다.
        // 현재 패킷의 seq + dataSize를 다시 계산하면 재전송/중복 segment에서
        // 이전 값이 들어갈 수 있으므로 FlowState의 nextSeq를 사용한다.
        const uint32_t clientNextSeq = it->second.nextSeq;
        const uint32_t serverNextSeq = it->second.serverNextSeq;

        // Forward: client -> server, Ethernet + IPv4 + TCP RST/ACK
        uint8_t forward[sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr)]{};

        EthHdr* fe = reinterpret_cast<EthHdr*>(forward);
        IpHdr* fi = reinterpret_cast<IpHdr*>(forward + sizeof(EthHdr));
        TcpHdr* ft = reinterpret_cast<TcpHdr*>(
            forward + sizeof(EthHdr) + sizeof(IpHdr)
        );

        fe->dmac_ = eth->dmac_;
        fe->smac_ = myMac;
        fe->type_ = htons(EthHdr::Ip4);

        fi->v_hl_ = 0x45;
        fi->tos_ = ip->tos_;
        fi->tlen_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
        fi->id_ = ip->id_;
        fi->off_ = 0;
        fi->ttl_ = 64;
        fi->p_ = IpHdr::TCP;
        fi->sip_ = ip->sip_;
        fi->dip_ = ip->dip_;

        ft->sport_ = tcp->sport_;
        ft->dport_ = tcp->dport_;
        ft->seq_ = htonl(clientNextSeq);
        ft->ack_ = htonl(serverNextSeq);
        ft->off_rsvd_ = 5 << 4;
        ft->flags_ = TcpHdr::RST | TcpHdr::ACK;

        ft->sum_ = tcpChecksum(fi, ft, sizeof(TcpHdr));
        fi->sum_ = checksum(reinterpret_cast<uint8_t*>(fi), sizeof(IpHdr));

        if (pcap_sendpacket(handle, forward, sizeof(forward)) != 0)
            fprintf(stderr, "forward send failed: %s\n", pcap_geterr(handle));

        // Backward: server -> client, raw IPv4 + TCP RST/ACK
        uint8_t backward[sizeof(IpHdr) + sizeof(TcpHdr)]{};

        IpHdr* bi = reinterpret_cast<IpHdr*>(backward);
        TcpHdr* bt = reinterpret_cast<TcpHdr*>(backward + sizeof(IpHdr));

        bi->v_hl_ = 0x45;
        bi->tos_ = ip->tos_;
        bi->tlen_ = htons(sizeof(backward));
        bi->id_ = ip->id_;
        bi->off_ = 0;
        bi->ttl_ = 64;
        bi->p_ = IpHdr::TCP;
        bi->sip_ = ip->dip_;
        bi->dip_ = ip->sip_;

        bt->sport_ = tcp->dport_;
        bt->dport_ = tcp->sport_;
        bt->seq_ = htonl(serverNextSeq);
        bt->ack_ = htonl(clientNextSeq);
        bt->off_rsvd_ = 5 << 4;
        bt->flags_ = TcpHdr::RST | TcpHdr::ACK;

        bt->sum_ = tcpChecksum(bi, bt, sizeof(TcpHdr));
        bi->sum_ = checksum(reinterpret_cast<uint8_t*>(bi), sizeof(IpHdr));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = bi->dip_;

        if (sendto(
                raw,
                backward,
                sizeof(backward),
                0,
                reinterpret_cast<sockaddr*>(&addr),
                sizeof(addr)
            ) < 0)
            perror("backward send");

        printf(
            "blocked SNI=%s %s:%u -> %s:%u "
            "forward(seq=%u ack=%u) backward(seq=%u ack=%u)\n",
            parsedHost.c_str(),
            string(ip->sip()).c_str(),
            uint16_t(tcp->sport()),
            string(ip->dip()).c_str(),
            uint16_t(tcp->dport()),
            clientNextSeq,
            serverNextSeq,
            serverNextSeq,
            clientNextSeq
        );

        flows.erase(it);
    }

    close(raw);
    pcap_close(handle);
    return 0;
}
