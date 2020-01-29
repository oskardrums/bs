use eui48::MacAddress;
use std::mem::{transmute, size_of};

pub const OFFSET_ETHER_SRC:   u16 = 6;
pub const OFFSET_ETHER_DST:   u16 = 0;
pub const OFFSET_ETHER_TYPE:  u16 = 12;
pub const OFFSET_IP_SRC:      u16 = 26;
pub const OFFSET_IP_DST:      u16 = 30;

pub fn mac_to_u32_and_u16(mac: MacAddress) -> (u32, u16) {
    let bytes = mac.to_array();
    unsafe {
        (
            transmute::<[u8; 4], u32>([bytes[0], bytes[1], bytes[2], bytes[3]]),
            transmute::<[u8; 2], u16>([bytes[4], bytes[5]]),
        )
    }
}


