//! Initialize a buffer with the iperf pattern.
//!
//! This is its own module to benchmark it individually.

/// Initialize a buffer with the full pattern.
///
/// The `offset` is the offset in the sequence, module 10.
#[inline]
pub fn init(mut buf: &mut [u8], offset: usize) {
    const DIGIT: &[u8] = include_bytes!("pattern.txt");

    assert!(offset < 10, "Invalid offset");
    // Align the buffer.
    if offset > 0 {
        if buf.len() <= 10 - offset {
            let source = &DIGIT[offset..offset+buf.len()];
            buf.copy_from_slice(source);
            return;
        }

        buf[..10 - offset].copy_from_slice(&DIGIT[offset..10]);
        buf = &mut buf[10 - offset..];
    }

    buf.chunks_mut(DIGIT.len())
        .for_each(|chunk| chunk.copy_from_slice(&DIGIT[..chunk.len()]));
}

#[bench]
#[cfg(feature = "bench")]
fn segment_1470(b: &mut test::Bencher) {
    let mut buffer = vec![0; 1470];
    b.iter(|| {
        init(&mut buffer, 0);
        test::black_box(&mut buffer);
    });
}

#[bench]
#[cfg(feature = "bench")]
fn segment_500(b: &mut test::Bencher) {
    let mut buffer = vec![0; 500];
    b.iter(|| {
        init(&mut buffer, 0);
        test::black_box(&mut buffer);
    });
}

#[bench]
#[cfg(feature = "bench")]
fn segment_100(b: &mut test::Bencher) {
    let mut buffer = vec![0; 100];
    b.iter(|| {
        init(&mut buffer, 0);
        test::black_box(&mut buffer);
    });
}

#[bench]
#[cfg(feature = "bench")]
fn segment_20(b: &mut test::Bencher) {
    let mut buffer = vec![0; 20];
    b.iter(|| {
        init(&mut buffer, 0);
        test::black_box(&mut buffer);
    });
}
