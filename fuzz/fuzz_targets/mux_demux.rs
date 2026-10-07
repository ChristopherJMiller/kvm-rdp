#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| kvm_proto::fuzzing::mux_demux(data));
