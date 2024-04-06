use argon2::Argon2;
use arrayvec::ArrayString;

// Since I plan to use Argon2 the password should be limited to avoid DoS
pub const MAX_USERNAME_LEN: usize = 512;
pub const MAX_PASSWORD_LEN: usize = 512;

pub type Username = ArrayString<MAX_USERNAME_LEN>;
// TODO: zeroize
pub type Password = ArrayString<MAX_PASSWORD_LEN>;

#[inline]
pub fn argon2() -> Argon2<'static> {
    Argon2::default()
}
