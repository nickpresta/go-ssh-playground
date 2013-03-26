# SSH Playground

![Powered by Gophers](http://i.imgur.com/SwkPj.png "Powered by Gophers")

This repo contains code that connects via SSH and does stuff. Ideally this would turn into a
[Fabric](http://docs.fabfile.org/en/1.6/)-like library for Go.

## Resources

Some files that help during implementation.

* [client\_auth.go](https://code.google.com/p/go/source/browse/ssh/client_auth.go?repo=crypto)
* [client\_auth\_test.go](https://code.google.com/p/go/source/browse/ssh/client_auth_test.go?repo=crypto)
* [openpgp](https://code.google.com/p/go/source/browse?repo=crypto#hg%2Fopenpgp)
* [openpgp/packet/encrypted\_key.go](https://code.google.com/p/go/source/browse/openpgp/packet/encrypted_key.go?repo=crypto)
* [openpgp/packet/encrypted\_key\_test.go](https://code.google.com/p/go/source/browse/openpgp/packet/encrypted_key_test.go?repo=crypto)

## License

Goscribe and Goscribed are released under the MIT license. See `LICENSE.md` for details.
