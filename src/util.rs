use std::{array::TryFromSliceError, borrow::Borrow};

use aes_gcm::{aead::generic_array::GenericArray, aes::cipher::ArrayLength};
use typenum::{Const, ToUInt};

// TODO: newer versions of GenericArray have infallible const-generic conversions
pub trait ArrayExt<T, const N: usize>
where
    Const<N>: ToUInt,
    <Const<N> as ToUInt>::Output: ArrayLength<T>,
{
    fn as_generic(&self) -> &GenericArray<T, <Const<N> as ToUInt>::Output>;
}

impl<T: Borrow<[U; N]>, U, const N: usize> ArrayExt<U, N> for T
where
    Const<N>: ToUInt,
    <Const<N> as ToUInt>::Output: ArrayLength<U>,
{
    fn as_generic(&self) -> &GenericArray<U, <Const<N> as ToUInt>::Output> {
        GenericArray::from_slice(self.borrow())
    }
}

pub trait SliceExt<T> {
    fn try_as_generic<const N: usize>(
        &self,
    ) -> Result<&GenericArray<T, <Const<N> as ToUInt>::Output>, TryFromSliceError>
    where
        Const<N>: ToUInt,
        <Const<N> as ToUInt>::Output: ArrayLength<T>;
}

impl<T: Borrow<[U]>, U> SliceExt<U> for T {
    fn try_as_generic<const N: usize>(
        &self,
    ) -> Result<&GenericArray<U, <Const<N> as ToUInt>::Output>, TryFromSliceError>
    where
        Const<N>: ToUInt,
        <Const<N> as ToUInt>::Output: ArrayLength<U>,
    {
        <&[U; N]>::try_from(self.borrow()).map(ArrayExt::as_generic)
    }
}
