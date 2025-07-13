fn main() {
    // Generate protobuf code
    prost_build::compile_protos(&["proto/flow.proto"], &["proto"])
        .unwrap();
} 