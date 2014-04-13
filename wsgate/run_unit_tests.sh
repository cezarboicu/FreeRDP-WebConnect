g++ unit_tests.cpp -o wsgate_unit_tests -DHAVE_CONFIG_H -I. -DBINDHELPER_PATH=\"/usr/local/libexec/wsgate/bindhelper\" -DDEFAULTCFG=\"/usr/local/etc/wsgate.ini\" -I/usr/include/casablanca -I/usr/include/ehs -g -fno-strict-aliasing  -std=c++11 -lboost_unit_test_framework
./wsgate_unit_tests
