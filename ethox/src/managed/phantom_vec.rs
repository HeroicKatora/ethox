//! A uninhabited type masquerading as `Vec<_>`.
#![allow(unused, dead_code)]

use core::marker::PhantomData;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vec<T> {
    elements: PhantomData<T>,
    data: Void,
}

impl<T> Vec<T> {
    pub fn as_slice(&self) -> &[T] {
        match self.data { }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self.data { }
    }

    pub fn resize(&mut self, len: usize, element: T) {
        match self.data { }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Void { }
