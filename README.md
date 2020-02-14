# bs
[![Build Status](https://travis-ci.com/oskardrums/bs.svg?token=xiZJWJ821dj7r3DoJgLH&branch=master)](https://travis-ci.com/oskardrums/bs)

Safe, sound, and all around *b*etter *s*ockets for Rust

## Examples
```rust
# use bs_system::Result;
# use bs_system::SystemError as Error;
# use bs_socket::socket::{BasicSocket, SetFilter};
# use std::net::IpAddr;
# use eui48::MacAddress;
use bs::{
    filter::{
        backend::Classic,
        idiom::{
            ip::ip_src,
            ethernet::ether_src,
        },
    },
    socket::{
        socket::Socket,
        packet::PacketLayer2Socket,
    },
};

# const IP_HEADER_LENGTH: usize = 20;
# const IP_SOURCE_START: usize = 12;
# const IP_SOURCE_END: usize = IP_SOURCE_START + 4;
# const PARSE_ERROR: i32 = 0;

fn raw_ethernet_only_loves_one_one_one_one(buffer: &mut [u8]) -> Result<()> {

    let vip = "1.1.1.1".parse().map_err(|_| Error(PARSE_ERROR))?;
    let my_gateway = "00:11:22:33:44:55".parse().map_err(|_| Error(PARSE_ERROR))?;

    let mut s: Socket<PacketLayer2Socket> = Socket::new()?;

    s.set_filter(
        // Generate kernel socket filters at runtime, just like that!
        ( ip_src::<Classic>(vip) & ether_src(my_gateway) )
            .compile()?
            .build()?
    )?;

    let got_this_many_bytes = s.receive(buffer, 0)?;

    assert!(got_this_many_bytes > IP_HEADER_LENGTH);
    assert_eq!([1, 1, 1, 1], buffer[IP_SOURCE_START..IP_SOURCE_END]);

    Ok(())
}
```

## Contributing
`bs` is a work in progress, and assistance is welcome.
Feel free to open pull requests or issues for changes and suggestions.

PR should include relevant tests and documentation, so please make sure you get those.


## License
[MIT](https://choosealicense.com/licenses/mit/)
