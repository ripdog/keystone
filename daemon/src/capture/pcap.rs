//! Counting the packets in a pcap byte stream as it is written.
//!
//! tcpdump writes the capture to a pipe, and the daemon only needs to know how
//! many packets have gone by. This reads the record headers and skips the
//! packet bytes; it never interprets a packet.

/// Longest captured packet a record may claim. A larger value means the stream
/// is not a pcap file, and counting stops rather than guessing.
const MAX_RECORD_BYTES: u32 = 262_144;
const GLOBAL_HEADER_BYTES: usize = 24;
const RECORD_HEADER_BYTES: usize = 16;

enum State {
    Global,
    Record,
    Body(u32),
    /// Not a pcap stream. Nothing more is counted.
    Invalid,
}

pub struct PcapCounter {
    state: State,
    header: Vec<u8>,
    big_endian: bool,
    packets: u64,
}

impl Default for PcapCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapCounter {
    pub fn new() -> Self {
        Self {
            state: State::Global,
            header: Vec::with_capacity(GLOBAL_HEADER_BYTES),
            big_endian: false,
            packets: 0,
        }
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// Whether the stream turned out not to be a pcap file.
    pub fn is_invalid(&self) -> bool {
        matches!(self.state, State::Invalid)
    }

    /// Account for the next bytes of the stream.
    pub fn feed(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            match self.state {
                State::Invalid => return,
                State::Global => {
                    data = self.fill_header(data, GLOBAL_HEADER_BYTES);
                    if self.header.len() == GLOBAL_HEADER_BYTES {
                        self.state = match self.header[..4] {
                            // Microsecond and nanosecond timestamps, each in
                            // either byte order.
                            [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => {
                                self.big_endian = false;
                                State::Record
                            }
                            [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => {
                                self.big_endian = true;
                                State::Record
                            }
                            _ => State::Invalid,
                        };
                        self.header.clear();
                    }
                }
                State::Record => {
                    data = self.fill_header(data, RECORD_HEADER_BYTES);
                    if self.header.len() == RECORD_HEADER_BYTES {
                        let raw = [
                            self.header[8],
                            self.header[9],
                            self.header[10],
                            self.header[11],
                        ];
                        let length = if self.big_endian {
                            u32::from_be_bytes(raw)
                        } else {
                            u32::from_le_bytes(raw)
                        };
                        self.header.clear();
                        if length > MAX_RECORD_BYTES {
                            self.state = State::Invalid;
                        } else {
                            self.packets += 1;
                            self.state = if length == 0 {
                                State::Record
                            } else {
                                State::Body(length)
                            };
                        }
                    }
                }
                State::Body(remaining) => {
                    let skipped = data.len().min(remaining as usize);
                    data = &data[skipped..];
                    let left = remaining - skipped as u32;
                    self.state = if left == 0 {
                        State::Record
                    } else {
                        State::Body(left)
                    };
                }
            }
        }
    }

    /// Move bytes from `data` into the header buffer until it holds `wanted`.
    fn fill_header<'a>(&mut self, data: &'a [u8], wanted: usize) -> &'a [u8] {
        let take = data.len().min(wanted - self.header.len());
        self.header.extend_from_slice(&data[..take]);
        &data[take..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian microsecond pcap with one record per given length.
    fn pcap(lengths: &[u32]) -> Vec<u8> {
        let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1];
        out.extend_from_slice(&[0; GLOBAL_HEADER_BYTES - 4]);
        for &length in lengths {
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(&length.to_le_bytes());
            out.extend(std::iter::repeat_n(0xab, length as usize));
        }
        out
    }

    #[test]
    fn counts_records_in_one_chunk() {
        let mut counter = PcapCounter::new();
        counter.feed(&pcap(&[60, 0, 1500]));
        assert_eq!(counter.packets(), 3);
        assert!(!counter.is_invalid());
    }

    #[test]
    fn counts_the_same_however_the_stream_is_split() {
        let data = pcap(&[60, 100, 1, 1500, 42]);
        for chunk in [1, 2, 7, 16, 25, 1000] {
            let mut counter = PcapCounter::new();
            for piece in data.chunks(chunk) {
                counter.feed(piece);
            }
            assert_eq!(counter.packets(), 5, "chunk size {chunk}");
        }
    }

    #[test]
    fn a_header_with_no_packets_yet_counts_none() {
        let mut counter = PcapCounter::new();
        counter.feed(&pcap(&[]));
        assert_eq!(counter.packets(), 0);
    }

    #[test]
    fn big_endian_and_nanosecond_files_are_read() {
        let mut data = vec![0xa1, 0xb2, 0x3c, 0x4d];
        data.extend_from_slice(&[0; GLOBAL_HEADER_BYTES - 4]);
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(&[1; 5]);
        let mut counter = PcapCounter::new();
        counter.feed(&data);
        assert_eq!(counter.packets(), 1);
    }

    #[test]
    fn a_stream_that_is_not_pcap_stops_counting() {
        let mut counter = PcapCounter::new();
        counter.feed(&[0x7f, b'E', b'L', b'F'].repeat(20));
        assert!(counter.is_invalid());
        assert_eq!(counter.packets(), 0);

        // An absurd record length is refused instead of skipping gigabytes.
        let mut data = pcap(&[]);
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&u32::MAX.to_le_bytes());
        data.extend_from_slice(&[0; 4]);
        let mut counter = PcapCounter::new();
        counter.feed(&data);
        assert!(counter.is_invalid());
        assert_eq!(counter.packets(), 0);
    }
}
