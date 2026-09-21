// afx/test_framework.hpp — minimal single-header test framework for the C++
// venue-connectivity suites (PHASE 1-4, PHASE 5 benches). No external dependencies.
//
// Usage:
//   AFX_TEST(my_test) { AFX_EXPECT(x); AFX_EXPECT_EQ(a, b); }
//   int main(int argc, char** argv) { return afx::run_all(argc, argv); }
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace afx {

struct TestCase {
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

struct Failure {
    const char* file;
    int line;
    std::string what;
};

struct TestRun {
    const TestCase* test = nullptr;
    std::vector<Failure> failures;
};

inline TestRun& current() {
    static TestRun t;
    return t;
}

inline void record_failure(const char* file, int line, const std::string& what) {
    current().failures.push_back({file, line, what});
}

inline int run_all(int argc, char** argv) {
    (void)argc;
    (void)argv;
    int failed_tests = 0;
    int passed_tests = 0;
    for (const auto& t : registry()) {
        current() = TestRun{&t, {}};
        t.fn();
        if (current().failures.empty()) {
            ++passed_tests;
            std::printf("[PASS] %s\n", t.name);
        } else {
            ++failed_tests;
            std::printf("[FAIL] %s\n", t.name);
            for (const auto& f : current().failures) {
                std::printf("       %s:%d: %s\n", f.file, f.line, f.what.c_str());
            }
        }
    }
    std::printf("== %d passed, %d failed, %zu total ==\n", passed_tests,
                failed_tests, registry().size());
    return failed_tests == 0 ? 0 : 1;
}

}  // namespace afx

#define AFX_CONCAT2(a, b) a##b
#define AFX_CONCAT(a, b) AFX_CONCAT2(a, b)
#define AFX_TEST(name)                                                         \
    static void name();                                                        \
    static ::afx::Registrar AFX_CONCAT(afx_reg_, name)(#name, &name);          \
    static void name()

#define AFX_EXPECT(cond)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            ::afx::record_failure(__FILE__, __LINE__,                          \
                                  "EXPECT failed: " #cond);                    \
        }                                                                      \
    } while (0)

#define AFX_EXPECT_EQ(a, b)                                                    \
    do {                                                                       \
        auto afx_va = (a);                                                     \
        auto afx_vb = (b);                                                     \
        if (!(afx_va == afx_vb)) {                                             \
            ::afx::record_failure(                                             \
                __FILE__, __LINE__,                                            \
                std::string("EXPECT_EQ failed: " #a " == " #b) +               \
                    "\n    left  = " + std::to_string(afx_va) +                \
                    "\n    right = " + std::to_string(afx_vb));                \
        }                                                                      \
    } while (0)

#define AFX_EXPECT_STREQ(a, b)                                                 \
    do {                                                                       \
        std::string afx_sa = (a);                                              \
        std::string afx_sb = (b);                                              \
        if (afx_sa != afx_sb) {                                                \
            ::afx::record_failure(                                             \
                __FILE__, __LINE__,                                            \
                std::string("EXPECT_STREQ failed: " #a " == " #b) +            \
                    "\n    left  = \"" + afx_sa + "\"" +                       \
                    "\n    right = \"" + afx_sb + "\"");                       \
        }                                                                      \
    } while (0)
