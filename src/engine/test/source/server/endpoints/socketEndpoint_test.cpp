
#include "testsSocketEndpoint.hpp"

#define GTEST_COUT cerr << "[          ] [ INFO ]"

using namespace engineserver;
using namespace engineserver::endpoints;
using namespace std;
using namespace rxcpp;

TEST(SocketTest, Initializes)
{
    const string config = "/tmp/testsocket";
    ASSERT_NO_THROW(SocketEndpoint socket(config));
}

TEST(SocketTest, Subscribe)
{
    const string config = "/tmp/testsocket";
    SocketEndpoint socket(config);
    socket.output().flat_map([](auto o) { return o; }).subscribe([](auto j) { GTEST_COUT << j.str() << endl; });
}
