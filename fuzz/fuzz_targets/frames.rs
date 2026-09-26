//! Frame parsing on arbitrary bodies: never panics, and every
//! frame that parses re-encodes to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use skyblock_proto::frame::{FrameReader, FrameWriter};

fuzz_target!(|data: &[u8]| {
    let mut consumed = 0;
    for frame in FrameReader::new(data) {
        let Ok(frame) = frame else { break };
        let mut buf = vec![0u8; frame.encoded_len()];
        let mut w = FrameWriter::new(&mut buf);
        w.write(&frame).expect("a parsed frame fits its own length");
        assert_eq!(w.len(), frame.encoded_len());
        assert_eq!(&buf[..], &data[consumed..consumed + buf.len()]);
        let again = FrameReader::new(&buf).next().unwrap().unwrap();
        assert_eq!(again, frame);
        consumed += buf.len();
    }
});
