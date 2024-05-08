void build(Solution &s) {
    auto &aspia = s.addProject("dns");

    auto cppstd = cpplatest;

    auto &testapp = aspia.addExecutable("testapp");
    {
        auto &t = testapp;
        t.PackageDefinitions = true;
        t += cppstd;
        t += "src/test/.*"_rr;
        t += "pub.egorpugin.primitives.sw.main"_dep;
        t += "org.sw.demo.boost.asio"_dep;
        t += "pub.egorpugin.primitives.templates2"_dep;
    }
}
