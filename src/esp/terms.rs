use crate::payload::DID_LEN;
use crate::service::ServiceDid;

/// Bytes of the terms: the service's DID (33) and the day (8).
pub const TERMS_BYTES: usize = DID_LEN + 8;

pub const SECONDS_PER_DAY: u64 = 86_400;
/// The default for how many days after issue a note becomes redeemable
/// (`terms.maturity_days`).
pub const REDEEM_WINDOW_DAYS: u64 = 365;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Terms {
    /// The service that may redeem the note: its AIR DID (33 bytes).
    pub service: ServiceDid,
    pub redeemable_after_day: u64,
}

impl Terms {
    /// Terms for a note issued at `now_unix`, redeemable after the default window.
    pub fn new_at(service: ServiceDid, now_unix: u64) -> Self {
        Self::new_at_days(service, now_unix, REDEEM_WINDOW_DAYS)
    }

    /// Terms for a note issued at `now_unix`, redeemable after `maturity_days`
    /// (the mint's `terms.maturity_days`).
    pub fn new_at_days(service: ServiceDid, now_unix: u64, maturity_days: u64) -> Self {
        Self {
            service,
            redeemable_after_day: (now_unix / SECONDS_PER_DAY).saturating_add(maturity_days),
        }
    }

    pub fn is_redeemable_at(&self, now_unix: u64) -> bool {
        now_unix / SECONDS_PER_DAY >= self.redeemable_after_day
    }

    /// The terms as they are hashed and signed: the service's 33-byte DID, then
    /// the day as 8 bytes big-endian (41 bytes).
    pub fn to_bytes(&self) -> [u8; TERMS_BYTES] {
        let mut out = [0u8; TERMS_BYTES];
        out[..DID_LEN].copy_from_slice(&self.service.serialize());
        out[DID_LEN..].copy_from_slice(&self.redeemable_after_day.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DID of G (the generator has an even y, so `02`).
    const G_DID: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn service() -> ServiceDid {
        ServiceDid::parse(G_DID).unwrap()
    }

    #[test]
    fn window_is_365_days_from_the_day_of_issue() {
        let terms = Terms::new_at(service(), 1_791_571_184);
        assert_eq!(terms.redeemable_after_day, 20_735 + 365);
        assert_eq!(terms.redeemable_after_day, 21_100);
    }

    #[test]
    fn the_window_can_be_set() {
        let terms = Terms::new_at_days(service(), 1_791_571_184, 30);
        assert_eq!(terms.redeemable_after_day, 20_735 + 30);
        let now = Terms::new_at_days(service(), 1_791_571_184, 0);
        assert_eq!(now.redeemable_after_day, 20_735);
        assert!(now.is_redeemable_at(1_791_571_184));
        assert_eq!(
            Terms::new_at_days(service(), 1_791_571_184, REDEEM_WINDOW_DAYS),
            Terms::new_at(service(), 1_791_571_184)
        );
    }

    #[test]
    fn time_of_day_does_not_change_the_terms() {
        let midnight = 20_735 * SECONDS_PER_DAY;
        let a = Terms::new_at(service(), midnight);
        let b = Terms::new_at(service(), midnight + SECONDS_PER_DAY - 1);
        assert_eq!(a, b);
        assert_ne!(a, Terms::new_at(service(), midnight + SECONDS_PER_DAY));
    }

    #[test]
    fn redeemable_from_the_start_of_the_day() {
        let terms = Terms::new_at(service(), 1_791_571_184);
        let start = terms.redeemable_after_day * SECONDS_PER_DAY;
        assert!(!terms.is_redeemable_at(0));
        assert!(!terms.is_redeemable_at(1_791_571_184));
        assert!(!terms.is_redeemable_at(start - 1));
        assert!(terms.is_redeemable_at(start));
        assert!(terms.is_redeemable_at(start + 10 * SECONDS_PER_DAY));
    }

    #[test]
    fn bytes_are_service_then_big_endian_day() {
        let bytes = Terms::new_at(service(), 1_791_571_184).to_bytes();
        assert_eq!(bytes.len(), 41);
        assert_eq!(hex::encode(&bytes[..33]), G_DID);
        assert_eq!(&bytes[33..], &21_100u64.to_be_bytes());
        // Built field by field, the terms are 41 bytes as well.
        let direct = Terms {
            service: service(),
            redeemable_after_day: 20_500,
        };
        assert_eq!(direct.to_bytes().len(), 41);
    }

    #[test]
    fn the_parity_byte_changes_the_terms() {
        let odd = ServiceDid::parse(&format!("03{}", &G_DID[2..])).unwrap();
        let a = Terms::new_at(service(), 1_791_571_184);
        let b = Terms::new_at(odd, 1_791_571_184);
        assert_ne!(a, b);
        assert_ne!(a.to_bytes(), b.to_bytes());
    }
}
