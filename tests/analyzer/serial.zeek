# @TEST-EXEC: zeek -C -r ${TRACES}/bsap-serial_example.pcapng %INPUT
# @TEST-EXEC: btest-diff bsap_serial_header.log
# @TEST-EXEC: btest-diff bsap_serial_rdb.log
#
# @TEST-DOC: Test BSAP analyzer with small BSAP serial trace.

@load icsnpp/bsap
