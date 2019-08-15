//! Tcp layer tests.
//!
//! For the lack of proper end-to-end connection testing—which would require a very lengthy setup
//! we instead tests components and pieces. A better test suite would implement some protocol on
//! top of tcp and test against other implementations. Due to the abundance of options and allowed
//! implementation specific behaviour it has proven quite hard to conduct this as a black-box test.
//! Hence, see also the example binary for tcp echo.
