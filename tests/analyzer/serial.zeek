# @TEST-EXEC: zeek -C -r ${TRACES}/bsap-serial_example.pcapng %INPUT
# @TEST-EXEC: btest-diff conn.log
#
# @TEST-DOC: Test BSAP analyzer with small BSAP serial trace.

@load icsnpp/bsap
