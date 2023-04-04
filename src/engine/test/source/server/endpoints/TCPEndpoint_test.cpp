
#include "testsTCPEndpoint.hpp"

#define GTEST_COUT cerr << "[          ] [ INFO ]"

using namespace engineserver;
using namespace engineserver::endpoints;
using namespace std;
using namespace rxcpp;

TEST(TCPTest, Initializes)
{
    const string config = "localhost:5054";
    ASSERT_NO_THROW(TCPEndpoint tcp(config));
}

TEST(TCPTest, RunStop)
{
    const string config = "localhost:5054";
    TCPEndpoint tcp(config);
    tcp.output().flat_map([](auto o) { return o; }).subscribe([](auto j) { GTEST_COUT << j.str() << endl; });
}
