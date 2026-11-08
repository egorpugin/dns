void build(Solution &s) {
    auto &dns = s.addProject("dns");

    auto cppstd = cpplatest;

#define SW_WITH_LOADER .set_loader([&](auto &t) {
#define SW_TARGET_END })
    auto &testapp = dns.addExecutable("testapp") SW_WITH_LOADER
        t.PackageDefinitions = true;
        t += cppstd;
        t += "src/test/.*"_rr;
        t += "pub.egorpugin.primitives.sw.main"_dep;
        t += "org.sw.demo.boost.asio"_dep;
        t += "pub.egorpugin.primitives.templates2"_dep;
    SW_TARGET_END;
}
