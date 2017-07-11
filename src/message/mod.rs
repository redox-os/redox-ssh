pub mod kex;

#[derive(Debug)]
pub enum Message {
    Disconnect,
    Ignore,
    Unimplemented,
    Debug,
    ServiceRequest,
    ServiceAccept,
    KexInit(kex::KeyExchangeInit),
    NewKeys,
    UserAuthRequest,
    UserAuthFailure,
    UserAuthSuccess,
    UserAuthBanner,
    GlobalRequest,
    RequestSuccess,
    RequestFailure,
    ChannelOpen,
    ChannelOpenConfirmation,
    ChannelOpenFailure,
    ChannelWindowAdjust,
    ChannelData,
    ChannelExtendedData,
    ChannelEOF,
    ChannelClose,
    ChannelRequest,
    ChannelSuccess,
    ChannelFailure,
    Unknown
}

