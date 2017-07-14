use std::fmt::Debug;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum MessageType {
    Disconnect,
    Ignore,
    Unimplemented,
    Debug,
    ServiceRequest,
    ServiceAccept,
    KexInit,
    NewKeys,
    KeyExchange(u8),
    UserAuthRequest,
    UserAuthFailure,
    UserAuthSuccess,
    UserAuthBanner,
    UserAuth(u8),
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

impl From<u8> for MessageType {
    fn from(id: u8) -> Self {
        use self::MessageType::*;
        match id {
            1 => Disconnect,
            2 => Ignore,
            3 => Unimplemented,
            4 => Debug,
            5 => ServiceRequest,
            6 => ServiceAccept,
            20 => KexInit,
            21 => NewKeys,
            30...49 => KeyExchange(id),
            50 => UserAuthRequest,
            51 => UserAuthFailure,
            52 => UserAuthSuccess,
            53 => UserAuthBanner,
            60...79 => UserAuth(id),
            80 => GlobalRequest,
            81 => RequestSuccess,
            82 => RequestFailure,
            90 => ChannelOpen,
            91 => ChannelOpenConfirmation,
            92 => ChannelOpenFailure,
            93 => ChannelWindowAdjust,
            94 => ChannelData,
            95 => ChannelExtendedData,
            96 => ChannelEOF,
            97 => ChannelClose,
            98 => ChannelRequest,
            99 => ChannelSuccess,
            100 => ChannelFailure,
            _ => Unknown
        }
    }
}

impl Into<u8> for MessageType {
    fn into(self) -> u8 {
        use self::MessageType::*;
        match self {
            Disconnect => 1,
            Ignore => 2,
            Unimplemented => 3,
            Debug => 4,
            ServiceRequest => 5,
            ServiceAccept => 6,
            KexInit => 20,
            NewKeys => 21,
            KeyExchange(id) => id,
            UserAuthRequest => 50,
            UserAuthFailure => 51,
            UserAuthSuccess => 52,
            UserAuthBanner => 53,
            UserAuth(id) => id,
            GlobalRequest => 80,
            RequestSuccess => 81,
            RequestFailure => 82,
            ChannelOpen => 90,
            ChannelOpenConfirmation => 91,
            ChannelOpenFailure => 92,
            ChannelWindowAdjust => 93,
            ChannelData => 94,
            ChannelExtendedData => 95,
            ChannelEOF => 96,
            ChannelClose => 97,
            ChannelRequest => 98,
            ChannelSuccess => 99,
            ChannelFailure => 100,
            Unknown => 255
        }
    }
}
