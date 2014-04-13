#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE wsgate_unit_tests
#include <boost/test/unit_test.hpp>
#include "RDP.hpp"
#include "Png.hpp"

BOOST_AUTO_TEST_SUITE(rdp_cpp_test_suite);

BOOST_AUTO_TEST_CASE(s1_test1)
{
//	wspp::MyWsHandler *ws = NULL;
//wsgate::RDP *rdp_instance = new wsgate::RDP(ws);
BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END();



BOOST_AUTO_TEST_SUITE(png_cpp_test_suite);

BOOST_AUTO_TEST_CASE(s2_test1)
{
wsgate::Png png_instance;
int w = 10;
int h = 10;

}

BOOST_AUTO_TEST_SUITE_END();

