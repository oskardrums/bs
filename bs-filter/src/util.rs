use eui48::MacAddress;
use std::mem::transmute;

#[allow(dead_code)]
pub const OFFSET_ETHER_SRC: u16 = 6;
#[allow(dead_code)]
pub const OFFSET_ETHER_DST: u16 = 0;
#[allow(dead_code)]
pub const OFFSET_ETHER_TYPE: u16 = 12;
#[allow(dead_code)]
pub const OFFSET_IP_SRC: u16 = 26;
#[allow(dead_code)]
pub const OFFSET_IP_DST: u16 = 30;

#[allow(dead_code)]
pub fn mac_to_u32_and_u16(mac: MacAddress) -> (u32, u16) {
    let bytes = mac.to_array();
    unsafe {
        (
            transmute::<[u8; 4], u32>([bytes[0], bytes[1], bytes[2], bytes[3]]),
            transmute::<[u8; 2], u16>([bytes[4], bytes[5]]),
        )
    }
}

use crate::{backend::Backend, Condition};
use crate::consts::BPF_JEQ;

#[allow(dead_code)]
pub(crate) fn ether_type<K: Backend>(ether_type: u16) -> Condition<K> {
    Condition::new(
        K::load_u16_at(OFFSET_ETHER_TYPE as _),
        K::Comparison::from(BPF_JEQ as u8),
        K::Value::from(ether_type as u32),
    )
}
