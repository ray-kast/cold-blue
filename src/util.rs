use std::{array::TryFromSliceError, borrow::Borrow, fmt};

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

impl<T, const N: usize> GenericArrayExt<T, N> for GenericArray<T, typenum::U<N>>
where
    Const<N>: ToUInt,
    typenum::U<N>: ArrayLength<T>,
{
    fn to_array(&self) -> [T; N]
    where T: Copy {
        self.as_slice().try_into().unwrap()
    }
}

pub trait ResultExt: Sized {
    type Output;
    type Error;

    fn erase_err_with<F, O: FnOnce() -> F>(self, msg: &str, op: O) -> Result<Self::Output, F>
    where Self::Error: Into<anyhow::Error>;

    fn erase_err_disp_with<F, O: FnOnce() -> F>(self, msg: &str, op: O) -> Result<Self::Output, F>
    where Self::Error: fmt::Display;

    fn anyhow_disp(self, msg: &str) -> Result<Self::Output, anyhow::Error>
    where Self::Error: fmt::Display;

    #[inline]
    fn erase_err<F>(self, msg: &str, err: F) -> Result<Self::Output, F>
    where Self::Error: Into<anyhow::Error> {
        self.erase_err_with(msg, || err)
    }

    #[inline]
    fn erase_err_disp<F>(self, msg: &str, err: F) -> Result<Self::Output, F>
    where Self::Error: fmt::Display {
        self.erase_err_disp_with(msg, || err)
    }
}

impl<T, E> ResultExt for Result<T, E> {
    type Error = E;
    type Output = T;

    #[inline]
    fn anyhow_disp(self, msg: &str) -> Result<Self::Output, anyhow::Error>
    where Self::Error: fmt::Display {
        self.map_err(|e| anyhow::anyhow!("{msg}: {e}"))
    }

    fn erase_err_with<F, O: FnOnce() -> F>(self, msg: &str, op: O) -> Result<Self::Output, F>
    where Self::Error: Into<anyhow::Error> {
        self.map_err(|e| {
            tracing::error!(err = ?e.into(), "{msg}");
            op()
        })
    }

    fn erase_err_disp_with<F, O: FnOnce() -> F>(self, msg: &str, op: O) -> Result<Self::Output, F>
    where Self::Error: fmt::Display {
        self.map_err(|err| {
            tracing::error!(%err, "{msg}");
            op()
        })
    }
}

pub trait TryIntoArray<T, const N: usize> {
    fn try_into_array(self, msg: &'static str) -> Result<[T; N], anyhow::Error>;
}

impl<S: AsRef<[T]> + TryInto<[T; N], Error = S>, T, const N: usize> TryIntoArray<T, N> for S {
    fn try_into_array(self, msg: &'static str) -> Result<[T; N], anyhow::Error> {
        self.try_into().map_err(|s| {
            anyhow::anyhow!(
                "Invalid length {} for {msg}, expected {N}",
                s.as_ref().len()
            )
        })
    }
}

pub trait OptionExt {
    type Output;

    fn ok_or_log<E>(self, msg: &str, err: E) -> Result<Self::Output, E>;
}

impl<T> OptionExt for Option<T> {
    type Output = T;

    fn ok_or_log<E>(self, msg: &str, err: E) -> Result<Self::Output, E> {
        self.ok_or_else(|| {
            tracing::error!("{msg}");
            err
        })
    }
}
