//! Host<->device request/response messages (the USB-CDC protocol payloads).
//!
//! Each message encodes as a flat CBOR array led by an integer tag: `[tag, ...fields]`.
//! `Request` (host -> device) and `Response` (device -> host) are separate enums with
//! separate tag spaces; the body bytes travel inside a frame (see the `frame` module).
//! Text fields are printable-ASCII (F15); byte fields borrow the input, zero-copy, like
//! the COSE and manifest types.
