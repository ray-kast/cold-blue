#![deny(
    clippy::disallowed_methods,
    clippy::suspicious,
    clippy::style,
    clippy::clone_on_ref_ptr
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(dead_code)] // TODO: remove when ready

pub(crate) mod agent;
mod boot;
pub(crate) mod commands;
pub(crate) mod db;
pub(crate) mod server;
pub(crate) mod util;

pub(crate) mod prelude {
    #![allow(unused_imports)]

    pub use std::{
        borrow::{
            Borrow, BorrowMut, Cow,
            Cow::{Borrowed, Owned},
        },
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        convert::Infallible,
        fmt,
        future::Future,
        hash::Hash,
        marker::PhantomData,
        mem,
        str::FromStr,
        sync::Arc,
    };

    pub use anyhow::{anyhow, bail, ensure, Context as _, Error};
    pub use chrono::prelude::*;
    pub use futures_util::{FutureExt, StreamExt, TryFutureExt, TryStreamExt};
    pub use tracing::{
        debug, debug_span, error, error_span, info, info_span, instrument, trace, trace_span, warn,
        warn_span, Instrument,
    };
    pub use tracing_subscriber::prelude::*;
    pub use url::Url;

    pub use crate::util::{ArrayExt, GenericArrayExt, ResultExt, SliceExt, TryIntoArray};

    pub type Result<T = (), E = Error> = std::result::Result<T, E>;
}

fn main() { boot::main() }
