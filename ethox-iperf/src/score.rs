use core::fmt;

use crate::iperf2;
use ethox::time::Duration;

/// The result of running the benchmark.
pub struct Score {
    /// The amount of data transferred from all arrived packets.
    pub(crate) data_len: u64,
    /// Duration from first to last packet to acknowledged.
    pub(crate) time: ethox::time::Duration,
    /// Number of successful packets that arrived.
    pub(crate) packet_count: u32,
    /// The number of packets that were sent.
    pub(crate) total_count: u32,
}

impl Score {
    fn total_kb(&self) -> u64 {
        self.data_len/1024
    }

    fn effective_rate(&self) -> f32 {
        (self.data_len as f32)/self.elapsed_secs()
    }

    fn elapsed_secs(&self) -> f32 {
        self.time.as_millis() as f32/1000.0
    }

    fn loss_rate(&self) -> f32 {
        (self.packet_count as f32)/(self.total_count as f32)
    }
}

impl From<iperf2::Result> for Score {
    fn from(result: iperf2::Result) -> Score {
        Score {
            data_len: result.data_len.into(),
            time: Duration::from_millis(
                u64::from(result.delta_s) * 1000 +
                u64::from(result.delta_ms)),
            packet_count: result.packet_count,
            total_count: result.total_count,
        }
    }
}

impl From<iperf2::TcpResult> for Score {
    fn from(result: iperf2::TcpResult) -> Score {
        // FIXME: should report total/vs. non-retransmit packets
        Score {
            data_len: result.data_len.into(),
            time: result.duration,
            packet_count: result.packet_count,
            total_count: result.packet_count,
        }
    }
}

impl From<iperf2::ServerResult> for Score {
    fn from(result: iperf2::ServerResult) -> Score {
        Score {
            data_len: result.received_bytes,
            time: result.duration,
            packet_count: result.packet_count,
            total_count: result.total_count,
        }
    }
}

impl fmt::Display for Score {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Emulate the iperf style:
        //
        // ```text
        // [  3]  0.0- 1.0 sec   131 KBytes  1.05 Mbits/sec   0.000 ms    0/   91 (0%)
        // ```
        write!(f,
           "[{ts}] {begin}-{end} sec\t{total} KBytes\t{rate} Mbits/sec\t{dt} ms\t\
            {loss}/\t{packets} ({loss_percent})",
           ts=3,
           begin=0.0,
           end=1.0,
           total=self.total_kb(),
           rate=self.effective_rate(),
           dt=0.0,
           loss=0,
           packets=self.packet_count,
           loss_percent=self.loss_rate()*100.0,
        )
    }
}
