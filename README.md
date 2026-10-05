# kvm-rdp

An RDP server for a commodity IP-KVM. It logs in to the KVM, passes the KVM's
H.264 video through to the RDP client untouched (EGFX AVC420, via
[IronRDP](https://github.com/Devolutions/IronRDP)), and turns the client's
keyboard and mouse into the KVM's USB-HID frames. Any RDP client — Windows
App on macOS included — can then drive whatever machine the KVM is plugged
into, with no browser and no re-encode.

The first target is the Angeet/Yeeso ES3 ("ONE KVM").

**Status:** design. Nothing runs yet.

> **Security note.** The ES3 has an unpatched pre-auth root RCE
> (CVE-2026-32297 / CVE-2026-32298). Never expose it to a network anything
> untrusted can reach; put it on an isolated segment that only this bridge
> can talk to, and treat its video stream as hostile input.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
