use std::{array::TryFromSliceError, borrow::Borrow};

use aes_gcm::{aead::generic_array::GenericArray, aes::cipher::ArrayLength};
use typenum::{Const, ToUInt};

// TODO: newer versions of GenericArray have infallible const-generic conversions
pub trait ArrayExt<T, const N: usize>
where
    Const<N>: ToUInt,
    typenum::U<N>: ArrayLength<T>,
{
    fn as_generic(&self) -> &GenericArray<T, typenum::U<N>>;
}

impl<T: Borrow<[U; N]>, U, const N: usize> ArrayExt<U, N> for T
where
    Const<N>: ToUInt,
    typenum::U<N>: ArrayLength<U>,
{
    fn as_generic(&self) -> &GenericArray<U, typenum::U<N>> {
        GenericArray::from_slice(self.borrow())
    }
}

pub trait SliceExt<T> {
    fn try_as_generic<const N: usize>(
        &self,
    ) -> Result<&GenericArray<T, typenum::U<N>>, TryFromSliceError>
    where
        Const<N>: ToUInt,
        typenum::U<N>: ArrayLength<T>;
}

impl<T: Borrow<[U]>, U> SliceExt<U> for T {
    fn try_as_generic<const N: usize>(
        &self,
    ) -> Result<&GenericArray<U, typenum::U<N>>, TryFromSliceError>
    where
        Const<N>: ToUInt,
        typenum::U<N>: ArrayLength<U>,
    {
        <&[U; N]>::try_from(self.borrow()).map(ArrayExt::as_generic)
    }
}

pub trait GenericArrayExt<T, const N: usize> {
    fn to_array(&self) -> [T; N]
    where T: Copy;
}

impl<T, const N: usize> GenericArrayExt<T, N>
    for GenericArray<T, typenum::U<N>>
where
    Const<N>: ToUInt,
    typenum::U<N>: ArrayLength<T>,
{
    fn to_array(&self) -> [T; N]
    where T: Copy {
        self.as_slice().try_into().unwrap()
    }
}
