use std::str;
use std::str::FromStr;
use nom::{IResult, Endianness};
use message::*;

macro_rules! enum_list (
    ($i:expr, $name:ty) => (
        parse_enum_list::<$name>($i)
    );
);

named!(pub parse_packet<Message>,
    map!(parse_keyx_init, |m| Message::KexInit(m))
);

named!(parse_keyx_init<&[u8], kex::KeyExchangeInit>, do_parse!(tag!(&[20]) >>
    cookie: take!(16) >>
    kex_algos: enum_list!(kex::KeyExchangeAlgorithm) >>
    server_host_key_algos: enum_list!(kex::HostKeyAlgorithm) >>
    enc_algos_c2s: enum_list!(kex::EncryptionAlgorithm) >>
    enc_algos_s2c: enum_list!(kex::EncryptionAlgorithm) >>
    mac_algos_c2s: enum_list!(kex::MacAlgorithm) >>
    mac_algos_s2c: enum_list!(kex::MacAlgorithm) >>
    comp_algos_c2s: enum_list!(kex::CompressionAlgorithm) >>
    comp_algos_s2c: enum_list!(kex::CompressionAlgorithm) >>
    langs_c2s: parse_name_list >>
    langs_s2c: parse_name_list >>
    first_kex_packet_follows: parse_bool >>
    reserved: u32!(Endianness::Big) >>
    (kex::KeyExchangeInit {
        cookie: cookie.to_vec(),
        kex_algorithms: kex_algos,
        server_host_key_algorithms: server_host_key_algos,
        encryption_algorithms_client_to_server: enc_algos_c2s,
        encryption_algorithms_server_to_client: enc_algos_s2c,
        mac_algorithms_client_to_server: mac_algos_c2s,
        mac_algorithms_server_to_client: mac_algos_s2c,
        compression_algorithms_client_to_server: comp_algos_c2s,
        compression_algorithms_server_to_client: comp_algos_s2c,
        languages_client_to_server:
            langs_c2s
            .iter()
            .filter(|s| !s.is_empty())
            .map(|lang| kex::Language(lang.to_string()))
            .collect(),
        languages_server_to_client:
            langs_c2s
            .iter()
            .filter(|s| !s.is_empty())
            .map(|lang| kex::Language(lang.to_string()))
            .collect(),
        first_kex_packet_follows: first_kex_packet_follows
    })
));

named!(parse_bool<&[u8], bool>,
    map!(take!(1), |i: &[u8]| i[0] != 0)
);

named!(parse_string<&[u8], &[u8]>,
       do_parse!(len: u32!(Endianness::Big) >>
                 data: take!(len) >>
                 (data)
       )
);

named!(parse_name_list<&[u8], Vec<&str>>,
       map_res!(parse_string, |s| str::from_utf8(s).map(|s| s.split(",").collect()))
);

pub fn parse_enum_list<T: FromStr>(i: &[u8]) -> IResult<&[u8], Vec<T>> {
    match parse_name_list(i) {
        IResult::Done(i, list) => IResult::Done(i,
                                                list.iter()
                                                .filter_map(|l| T::from_str(&l).ok())
                                                .collect()
        ),
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(n) => IResult::Incomplete(n)
    }
}
