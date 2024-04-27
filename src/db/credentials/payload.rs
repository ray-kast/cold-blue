use std::ops::{Deref, DerefMut};

use crate::{
    agent::{Agent, AgentManager},
    prelude::*,
};

#[derive(Default)]
pub struct CredentialBuilder {
    server: Option<Url>,
    username: Option<String>,
    password: Option<String>,
}

macro_rules! cb_field {
    ($name:ident : $ty:ty $(, $($($rest:tt)+)?)?) => {
        pub fn $name(mut self, $name: $ty) -> Self {
            self.$name = Some($name);
            self
        }

        $($(cb_field!($($rest)+);)?)?
    };
}

macro_rules! cb_assert {
    ($lit:literal => $name:ident $(, $($($rest:tt)+)?)?) => {
        assert!($name.is_none(), concat!("Unused ", $lit, " definition in credentials"));

        $($(cb_assert!($($rest)+);)?)?
    };
}

macro_rules! cb_take {
    ($lit:literal => $expr:expr) => {
        $expr
            .take()
            .expect(concat!("Missing ", $lit, " definition in credentials"))
    };
}

// TODO: maybe use macros for this?
impl CredentialBuilder {
    cb_field! {
        server: Url,
        username: String,
        password: String,
    }

    #[inline]
    pub fn new() -> Self { Self::default() }

    fn build<T, F: FnOnce(&mut Self) -> T>(mut self, payload: F) -> T {
        let payload = payload(&mut self);

        let Self {
            server,
            username,
            password,
        } = self;

        cb_assert! {
            "server" => server,
            "username" => username,
            "password" => password,
        };

        payload
    }

    pub fn build_atproto(self) -> AtProtoCredential {
        self.build(|this| AtProtoCredential {
            server: cb_take!("server" => this.server),
            username: cb_take!("username" => this.username),
            password: cb_take!("password" => this.password),
        })
    }
}

pub trait PayloadKind {
    const KIND: &'static str;

    fn ref_kind(&self) -> &'static str { Self::KIND }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CredentialPayload {
    AtProto(AtProtoCredential),
}

impl PayloadKind for CredentialPayload {
    const KIND: &'static str = stringify!(PayloadKind);

    fn ref_kind(&self) -> &'static str {
        match self {
            Self::AtProto(a) => a.ref_kind(),
        }
    }
}

impl PayloadKind for Infallible {
    const KIND: &'static str = "!";

    #[inline]
    fn ref_kind(&self) -> &'static str { match *self {} }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Named<T> {
    pub name: String,
    #[serde(flatten)]
    pub(super) payload: T,
}

impl<T> Deref for Named<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target { &self.payload }
}

impl<T> DerefMut for Named<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.payload }
}

macro_rules! credential_type {
    ($var:ident : $ty:ty $(, $($($rest:tt)+)?)?) => {
        impl From<$ty> for CredentialPayload {
            #[inline]
            fn from(val: $ty) -> Self { Self::$var(val) }
        }

        impl TryFrom<CredentialPayload> for $ty {
            type Error = CredentialPayload;

            #[inline]
            fn try_from(val: CredentialPayload) -> Result<Self, Self::Error> {
                if let CredentialPayload::$var(val) = val {
                    Ok(val)
                } else {
                    Err(val)
                }
            }
        }

        impl PayloadKind for $ty {
            const KIND: &'static str = stringify!($var);
        }

        $($(credential_type!($($rest)+);)?)?
    };
}

credential_type! {
    AtProto: AtProtoCredential,
}

pub type NamedAtProtoCredential = Named<AtProtoCredential>;

// TODO: zeroize
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtProtoCredential {
    pub server: Url,
    pub username: String,
    password: String,
}

impl AtProtoCredential {
    #[inline]
    pub fn login<'a>(&'a self, mgr: &'a AgentManager) -> impl Future<Output = Result<Agent>> + 'a {
        mgr.login(&self.server, &self.username, &self.password)
    }
}
