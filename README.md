# rustls self signed cert demo

This is a quick proof of concept that demonstrates:

* using `rcgen` to create a CA cert for a server
* determining local IP addresses using the `local-ip-address` crate
* creating ephemeral leaf certificates using the generated CA certificate
* hosting a TCP/TLS server using these certs using `rustls` (with `ring` as a provider)
* connecting to the TCP/TLS server from a client using `rustls` (with `ring` as a provider)

In general, the `rustls` [doesn't like using ca certs directly]:

> rustls does not and will not support... Using CA certificates directly to authenticate a
> server/client (often called “self-signed certificates”). Rustls’ default certificate
> verifier does not support using a trust anchor as both a CA certificate and an end-entity
> certificate in order to limit complexity and risk in path building. While dangerous,
> all authentication can be turned off if required – see the example code

[doesn't like using ca certs directly]: https://docs.rs/rustls/latest/rustls/manual/_04_features/index.html#non-features

Which is a reasonable choice to make. Additionally, `rustls` will verify the "Subject
Alternative Names", or SANs, are accurate when the client connects to the server. This
means if you are using an IP address to connect to the server, that IP address needs to
be encoded in the generated certificate.

So, this demo is useful if you want a template for ad-hoc, asymmetric crypto, using the
`rustls` stack, and using `ring`, which I believe means you don't need to mess with
linking in TLS stacks from the host environment.

I am not an expert at `rustls`, this is basically gluing together a lot of demos. Take it
with a grain of salt and a security review.

## License

All code MIT/Apache 2.0, Copyright OneVariable GmbH 2025
