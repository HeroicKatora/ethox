//! A uninhabited type masquerading as `Vec<_>`.
#![allow(unused, dead_code)]

use core::borrow::{Borrow, BorrowMut};
use core::marker::PhantomData;
use core::ops::RangeBounds;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vec<T> {
    elements: PhantomData<T>,
    data: Void,
}

pub struct Drain<'a, T> {
    elements: PhantomData<&'a [T]>,
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

    pub fn drain<R>(&mut self, idx: R) -> Drain<'_, T> 
        where R: RangeBounds<usize>
    {
        match self.data { }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Void { }

impl<T> Borrow<[T]> for Vec<T> {
    fn borrow(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> BorrowMut<[T]> for Vec<T> {
    fn borrow_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T> Iterator for Drain<'_, T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        match self.data { }
    }
}
