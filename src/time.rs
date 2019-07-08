/*! Time structures.

The `time` module contains structures used to represent both
absolute and relative time.

 - [Instant] is used to represent absolute time.
 - [Duration] is used to represet relative time.

[Instant]: struct.Instant.html
[Duration]: struct.Duration.html
*/
use core::{cmp, fmt, ops};
pub use core::time::Duration;

/// A representation of an absolute time value.
///
/// The `Instant` type is a wrapper around a `i64` value that
/// represents a number of milliseconds, monotonically increasing
/// since an arbitrary moment in time, such as system startup.
///
/// * A value of `0` is inherently arbitrary.
/// * A value less than `0` indicates a time before the starting
///   point.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    pub millis: i64,
}

/// An expiration time, inversion of `Option`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiration {
    When(Instant),
    Never,
}

use Expiration::{When, Never};

impl Instant {
    /// Create a new `Instant` from a number of milliseconds.
    pub fn from_millis<T: Into<i64>>(millis: T) -> Instant {
        Instant { millis: millis.into() }
    }

    /// Create a new `Instant` from a number of seconds.
    pub fn from_secs<T: Into<i64>>(secs: T) -> Instant {
        Instant { millis: secs.into() * 1000 }
    }

    /// Create a new `Instant` from the current [std::time::SystemTime].
    ///
    /// See [std::time::SystemTime::now]
    ///
    /// [std::time::SystemTime]: https://doc.rust-lang.org/std/time/struct.SystemTime.html
    /// [std::time::SystemTime::now]: https://doc.rust-lang.org/std/time/struct.SystemTime.html#method.now
    #[cfg(feature = "std")]
    pub fn now() -> Instant {
        Self::from(::std::time::SystemTime::now())
    }

    /// The fractional number of milliseconds that have passed
    /// since the beginning of time.
    pub fn millis(&self) -> i64 {
        self.millis % 1000
    }

    /// The number of whole seconds that have passed since the
    /// beginning of time.
    pub fn secs(&self) -> i64 {
        self.millis / 1000
    }

    /// The total number of milliseconds that have passed since
    /// the biginning of time.
    pub fn total_millis(&self) -> i64 {
        self.millis
    }
}

#[cfg(feature = "std")]
impl From<::std::time::Instant> for Instant {
    fn from(other: ::std::time::Instant) -> Instant {
        let elapsed = other.elapsed();
        Instant::from_millis((elapsed.as_secs() * 1_000) as i64 + (elapsed.subsec_nanos() / 1_000_000) as i64)
    }
}

#[cfg(feature = "std")]
impl From<::std::time::SystemTime> for Instant {
    fn from(other: ::std::time::SystemTime) -> Instant {
        let n = other.duration_since(::std::time::UNIX_EPOCH)
            .expect("start time must not be before the unix epoch");
        Self::from_millis(n.as_secs() as i64 * 1000 + (n.subsec_nanos() / 1000000) as i64)
    }
}

#[cfg(feature = "std")]
impl Into<::std::time::SystemTime> for Instant {
    fn into(self) -> ::std::time::SystemTime {
        ::std::time::UNIX_EPOCH + ::std::time::Duration::from_millis(self.millis as u64)
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}s", self.secs(), self.millis())
    }
}

impl ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        Instant::from_millis(self.millis + rhs.as_millis() as i64)
    }
}

impl ops::AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        self.millis += rhs.as_millis() as i64;
    }
}

impl ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Instant {
        Instant::from_millis(self.millis - rhs.as_millis() as i64)
    }
}

impl ops::SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        self.millis -= rhs.as_millis() as i64;
    }
}

impl ops::Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Instant) -> Duration {
        Duration::from_millis((self.millis - rhs.millis).abs() as u64)
    }
}

impl Default for Expiration {
    fn default() -> Self {
        Expiration::Never
    }
}

impl From<Option<Instant>> for Expiration {
    fn from(opt: Option<Instant>) -> Self {
        match opt {
            Some(instant) => When(instant),
            None => Never,
        }
    }
}

impl From<Expiration> for Option<Instant> {
    fn from(opt: Expiration) -> Self {
        match opt {
            When(instant) => Some(instant),
            Never => None,
        }
    }
}

impl cmp::PartialOrd<Self> for Expiration {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        match (*self, *other) {
            (Never, Never) => Some(cmp::Ordering::Equal),
            (Never, When(_)) => Some(cmp::Ordering::Greater),
            (When(_), Never) => Some(cmp::Ordering::Less),
            (When(ref a), When(ref b)) => a.partial_cmp(b),
        }
    }
}

impl cmp::Ord for Expiration {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (*self, *other) {
            (Never, Never) => cmp::Ordering::Equal,
            (Never, When(_)) => cmp::Ordering::Greater,
            (When(_), Never) => cmp::Ordering::Less,
            (When(ref a), When(ref b)) => a.cmp(b),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_instant_ops() {
        // std::ops::Add
        assert_eq!(Instant::from_millis(4) + Duration::from_millis(6), Instant::from_millis(10));
        // std::ops::Sub
        assert_eq!(Instant::from_millis(7) - Duration::from_millis(5), Instant::from_millis(2));
    }

    #[test]
    fn test_instant_getters() {
        let instant = Instant::from_millis(5674);
        assert_eq!(instant.secs(), 5);
        assert_eq!(instant.millis(), 674);
        assert_eq!(instant.total_millis(), 5674);
    }

    #[test]
    fn test_instant_display() {
        assert_eq!(format!("{}", Instant::from_millis(5674)), "5.674s");
        assert_eq!(format!("{}", Instant::from_millis(5000)), "5.0s");
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_instant_conversions() {
        let mut epoc: ::std::time::SystemTime = Instant::from_millis(0).into();
        assert_eq!(Instant::from(::std::time::UNIX_EPOCH),
                   Instant::from_millis(0));
        assert_eq!(epoc, ::std::time::UNIX_EPOCH);
        epoc = Instant::from_millis(2085955200i64 * 1000).into();
        assert_eq!(epoc, ::std::time::UNIX_EPOCH + ::std::time::Duration::from_secs(2085955200));
    }

    #[test]
    fn test_duration_ops() {
        // std::ops::Add
        assert_eq!(Duration::from_millis(40) + Duration::from_millis(2), Duration::from_millis(42));
        // std::ops::Sub
        assert_eq!(Duration::from_millis(555) - Duration::from_millis(42), Duration::from_millis(513));
        // std::ops::Mul
        assert_eq!(Duration::from_millis(13) * 22, Duration::from_millis(286));
        // std::ops::Div
        assert_eq!((Duration::from_millis(53) / 4).as_millis(), 13);
    }

    #[test]
    fn test_duration_assign_ops() {
        let mut duration = Duration::from_millis(4735);
        duration += Duration::from_millis(1733);
        assert_eq!(duration, Duration::from_millis(6468));
        duration -= Duration::from_millis(1234);
        assert_eq!(duration, Duration::from_millis(5234));
        duration *= 4;
        assert_eq!(duration, Duration::from_millis(20936));
        duration /= 5;
        assert_eq!(duration.as_millis(), 4187);
    }

    #[test]
    #[should_panic(expected = "overflow when subtracting durations")]
    fn test_sub_from_zero_overflow() {
        let _ = Duration::from_millis(0) - Duration::from_millis(1);
    }

    #[test]
    #[should_panic(expected = "divide by zero")]
    fn test_div_by_zero() {
        let _ = Duration::from_millis(4) / 0;
    }

    #[test]
    fn test_duration_getters() {
        let instant = Duration::from_millis(4934);
        assert_eq!(instant.as_secs(), 4);
        assert_eq!(instant.subsec_millis(), 934);
        assert_eq!(instant.as_millis(), 4934);
    }

    #[test]
    fn test_duration_conversions() {
        let mut std_duration = ::core::time::Duration::from_millis(4934);
        let duration: Duration = std_duration.into();
        assert_eq!(duration, Duration::from_millis(4934));
        assert_eq!(Duration::from(std_duration), Duration::from_millis(4934));

        std_duration = duration.into();
        assert_eq!(std_duration, ::core::time::Duration::from_millis(4934));
    }
}
