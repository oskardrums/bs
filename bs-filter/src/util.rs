pub use eui48::MacAddress;
pub use std::net::Ipv4Addr;
use std::mem::transmute;

pub const OFFSET_ETHER_SRC: u32 = 6;
pub const OFFSET_ETHER_DST: u32 = 0;
pub const OFFSET_ETHER_TYPE: u32 = 12;
pub const OFFSET_IP_SRC: u32 = 26;
pub const OFFSET_IP_DST: u32 = 30;
pub const OFFSET_IP_PROTO: u32 = 23;

#[allow(dead_code)]
pub fn mac_to_u32_and_u16(mac: MacAddress) -> (u32, u16) {
    let bytes = mac.to_array();
    unsafe {
        (
            transmute::<[u8; 4], u32>([bytes[0], bytes[1], bytes[2], bytes[3]]).to_be(),
            transmute::<[u8; 2], u16>([bytes[4], bytes[5]]).to_be(),
        )
    }
}

use crate::{backend::Backend, Condition};
use crate::consts::BPF_JEQ;

pub(crate) fn ether_type<K: Backend>(ether_type: u16) -> Condition<K> {
    Condition::new(
        K::load_u16_at(OFFSET_ETHER_TYPE),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(ether_type as u32),
    )
}
