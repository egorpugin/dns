// #include <router_relay/router.h>
#include <boost/asio.hpp>
#include <iostream>
#include <ranges>
#include <variant>

using namespace std::literals;
namespace ip = boost::asio::ip;

template <typename T = void>
using task = boost::asio::awaitable<T>;

// https://www.ietf.org/rfc/rfc1035.txt
struct dns_packet {
    template <typename T> struct be {
        static_assert(sizeof(T) > 1, "must be greater than 1 byte");

        T value;

        be &operator=(const be &) = default;
        be &operator=(auto &&in) {
            value = in;
            swap();
            return *this;
        }
        be &operator++() {
            swap();
            ++value;
            swap();
            return *this;
        }
        operator auto() const {
            return std::byteswap(value);
        }

    private:
        void swap() {
            value = std::byteswap(value);
        }
    };
    struct type {
        enum {
            A       = 1,    // a host address
            NS,             // an authoritative name server
            MD,
            MF,
            CNAME,          // the canonical name for an alias
            SOA,            // marks the start of a zone of authority
            MB,             // a mailbox domain name (EXPERIMENTAL)
            MG,
            MR,
            NULL_,
            WKS,            // a well known service description
            PTR,            // a domain name pointer
            HINFO,
            MINFO,
            MX,             // mail exchange
            TXT,            // text strings

            HTTPS = 63,
        };
    };
    struct qtype : type {
        enum {
            AXFR    = 252,
            MAILB,
            MAILA,
            ALL_RECORDS = 255,

            URI = 256,
        };
    };
    struct class_ {
        enum {
            IN_ = 1,
            INTERNET = 1,
            CS,
            CH,
            HS,
        };
    };
    struct qclass : class_ {
        enum {
            ALL_RECORDS = 255,
        };
    };

    struct label {
        uint8_t length;
        uint8_t name[0];

        operator std::string_view() {
            return std::string_view{(char *)&name[0], (char *)&name[0] + length};
        }
    };
    struct pointer {
        be<uint16_t> value;

        auto offset() const {
            uint16_t v = value;
            v &= 0x3fff;
            return v;
        }
    };
    struct header {
        be<uint16_t> id;
        // BE order
        uint16_t rd     : 1;
        uint16_t tc     : 1;
        uint16_t aa     : 1;
        uint16_t opcode : 4;
        uint16_t qr     : 1;
        uint16_t rcode  : 4;
        uint16_t z      : 3; // empty field
        uint16_t ra     : 1;
        //
        be<uint16_t> qdcount;
        be<uint16_t> ancount;
        be<uint16_t> nscount;
        be<uint16_t> arcount;
    };
    struct question_type {
        struct end_type {
            be<uint16_t> qtype;
            be<uint16_t> qclass;
        };
        auto next_label() {
            auto p = (uint8_t *)this;
            while (*p) {
                p += 1 + *p;
            }
            return (label *)p;
        }
        void add_qname(auto &&qname) {
            auto p = next_label();
            p->length = qname.size();
            memcpy(p->name, qname.data(), p->length);
        }
        auto &labels_end(dns_packet &p) {
            return *(end_type *)p.labels((uint8_t *)this, [](auto){});
        }
        auto end(dns_packet &p) {
            auto qe = (uint8_t *)&labels_end(p);
            qe += sizeof(question_type::end_type);
            return (uint8_t *)qe;
        }
    };
    struct resource {
#pragma pack(push, 1)
        struct resource_end {
            be<uint16_t> type;
            be<uint16_t> class_;
            be<uint32_t> ttl;
            be<uint16_t> rdlength;
            uint8_t rdata[0]; // custom data
        };
#pragma pack(pop)

        uint16_t name; // varlen

        resource_end &end() {
            //return
        }
    };

    header h;
    // resource authority; // multiple
    // resource additional; // multiple

    auto &question() {
        auto p = (uint8_t *)&h;
        p += sizeof(h);
        return *(question_type *)p;
    }
    void set_question(const std::string &qname, uint16_t qtype, uint16_t qclass) {
        for (auto &&[b,e] : std::views::split(qname, "."sv)) {
            std::string_view sv{b, e};
            if (sv.size() > 64) {
                throw std::runtime_error{"bad label length (must be < 64)"};
            }
            question().add_qname(sv);
        }
        question().labels_end(*this).qtype = qtype;
        question().labels_end(*this).qclass = qclass;
        ++h.qdcount;
    }
    std::string string_at(auto &&start) {
        std::string s;
        for (auto &l : labels(start)) {
            s += l;
            s += ".";
        }
        if (!s.empty()) {
            s.pop_back();
        }
        return s;
    }
    std::vector<std::string_view> labels(auto &&start) {
        std::vector<std::string_view> r;
        start = labels(start, [&](auto sv) {r.push_back(sv);});
        return r;
    }
    uint8_t *labels(uint8_t *start, auto &&f) {
        again:
        if (*start >= 64) {
            auto &ptr = *(pointer*)start;
            auto labs = labels((uint8_t *)&h + ptr.offset());
            for (auto &&l : labs) {
                f(l);
            }
            start += 2;
        } else if (*start == 0) {
            // end
            ++start;
        } else {
            std::string_view v = *(label *)start;
            f(v);
            start += 1 + v.size();
            goto again;
        }
        return start;
    }

    struct a {
        uint32_t ttl;
        std::string name;
        uint32_t address; // ipv4, be
    };
    struct cname {
        uint32_t ttl;
        std::string name;
        std::string cname;
    };
    using record_type = std::variant<a, cname>;
    auto answers() {
        std::vector<record_type> results;
        auto p = question().end(*this);
        uint16_t nres = h.ancount;
        while (nres--) {
            auto name = string_at(p);
            auto &res = *(resource::resource_end*)p;
            p += sizeof(res);
            switch (res.type) {
            case qtype::A: {
                a r;
                r.ttl = res.ttl;
                r.name = std::move(name);
                r.address = *(decltype(r.address)*)p; // swap bytes?
                results.push_back(r);
                break;
            }
            case qtype::CNAME: {
                cname r;
                r.ttl = res.ttl;
                r.name = std::move(name);
                r.cname = string_at(p);
                results.push_back(r);
                break;
            }
            default:
                throw std::runtime_error{"unimplemented"};
            }
        }
        return results;
    }

    size_t size() {
        return question().end(*this) - (uint8_t*)&h;
    }
};

struct dns_server {
    std::vector<std::string> dns_servers;

    auto query(const std::string &domain) {
        // asio transport for now
        boost::asio::io_context ctx;
        boost::asio::co_spawn(ctx, query_udp("gql.twitch.tv"s), boost::asio::detached);
        ctx.run();
    }
};

task<> query_udp(std::string domain) {
    auto ex = co_await boost::asio::this_coro::executor;
    ip::udp::endpoint e(ip::address_v4::from_string("8.8.8.8"), 53);
    ip::udp::socket s(ex);
    s.open(ip::udp::v4());
    constexpr auto udp_packet_max_size = 512;
    uint8_t buffer[udp_packet_max_size]{};
    auto &p = *(dns_packet*)buffer;
    p.h.id = 123;
    p.h.rd = 1;
    p.set_question(domain, dns_packet::qtype::A, dns_packet::qclass::INTERNET);
    co_await s.async_send_to(boost::asio::buffer(buffer, p.size()), e, boost::asio::use_awaitable);
    co_await s.async_receive_from(boost::asio::buffer(buffer), e, boost::asio::use_awaitable);
    auto answ = p.answers();
    if (p.h.ra && p.h.rd) {
        co_await s.async_send_to(boost::asio::buffer(&buffer, sizeof(buffer)), e, boost::asio::use_awaitable);
        co_await s.async_receive_from(boost::asio::buffer(&buffer, sizeof(buffer)), e, boost::asio::use_awaitable);

        int a = 5;
        a++;
    }

    //auto &p2 = *(dns_packet *)&buffer;
    //std::cout << p.h.id << "\n";
    //printf("%d\n", p.h.id);
    //std::cout << p2.h.id << "\n";
    int a = 5;
    a++;
}

int main(int argc, char *argv[]) {
    dns_server serv{{"8.8.8.8"}};
    serv.query("gql.twitch.tv"s);

    //boost::asio::io_context ctx;
    //boost::asio::co_spawn(ctx, query_udp("com."s), boost::asio::detached);
    //boost::asio::co_spawn(ctx, query_udp("www.youtube.com"s), boost::asio::detached);
    //boost::asio::co_spawn(ctx, query_udp("google.com"s), boost::asio::detached);
    //boost::asio::co_spawn(ctx, query_udp("egorpugin.ru"s), boost::asio::detached);
    //boost::asio::co_spawn(ctx, query_udp("aspia.egorpugin.ru"s), boost::asio::detached);
    //boost::asio::co_spawn(ctx, query_udp("gql.twitch.tv"s), boost::asio::detached);
    //ctx.run();
    return 0;
}