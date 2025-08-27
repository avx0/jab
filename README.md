# WARNING: Currently there is an RCE bug in jab. The code is in alpha stage.

# jab

jab is a console XMPP client.

- Supports PGP encrypted + signed messages.
- Per-session per-recipient private and public keys.
- Builds on existing infrastructure by being XMPP compliant.
- SOCKS proxies are supported.
- Users can proxy their connection through TOR.

# jab-v1

- [ ] make /list work. current workaround: open another jab connection, query server from there.
- [ ] TODO test jab <---> jab on different machines/VMs
- [ ] TODO add error handling to auth() (and last message verification) and other functions + make it work with popuar jabber services (yax.im works with default auth(), conversations.im doesn't)
- [ ] TODO implement SCRAM-SHA-1-PLUS to prevent mitm (supposedly). read the rfc.
- [ ] TODO fix the RCE bug.
- [X] jab (PGP+MAM) <--- anyPublicJabberServer <----> anyPublicJabberServer ----> jab (PGP+MAM)
- [X] TODO --my-key and --recp-key flags
- [X] TODO implement MAM (xep-0313)
- [X] DONE workaround for when user2 sends string while user1 is entering his string
- [X] DONE async read-write raw stanzas
- [X] DONE print some stuff to stderr (debug) -- created log_r() and log_w()
- [X] DONE implement current_GPG (xep-0027)

# jab-v2

- [ ] TODO make writing to conversations (openpgp) work
- [ ] TODO implement OTR
- [ ] TODO implement OMEMO
- [ ] TODO add buddy list handling


