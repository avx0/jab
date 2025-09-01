**WARNING**: Currently there is an **RCE bug** in jab. The code is in beta stage.

# jab

jab is a console XMPP client.

- Supports PGP encrypted + signed messages.
- Per-session per-recipient private and public keys.
- Builds on existing infrastructure by being XMPP compliant.
- SOCKS proxies are supported.
- Users can proxy their connection through TOR.

## Usage

```sh
proxychains4 -q                 \
	./jab.py                    \
	    --from bob@xmpp.tld     \
	    --to alice@xmpp.tld     \
	    --pass pass/pass_bob    \
	    --my-keyid bob          \
	    --recp-keyid alice
```


## jab-v1
- [ ] TODO rewrite in C
- [ ] TODO implement OTR
- [ ] TODO implement OMEMO
- [ ] TODO add buddy list handling

## jab-v0.1 (beta stage)

- [ ] TODO fix the RCE bug.
- [ ] TODO make /list work. current workaround: open another jab connection, query server from there.
- [ ] TODO test jab <---> jab on different machines/VMs
- [ ] TODO add error handling to auth() (and last message verification) and other functions + make it work with popuar jabber services (yax.im works with default auth(), conversations.im doesn't)
- [ ] TODO implement SCRAM-SHA-1-PLUS to prevent mitm (supposedly). read the rfc.
- [ ] TODO make writing to conversations (openpgp) work

## jab-prototype (alpha stage)

- [X] DONE jab (PGP+MAM) <--- anyPublicJabberServer <----> anyPublicJabberServer ----> jab (PGP+MAM)
- [X] DONE --my-key and --recp-key flags
- [X] DONE implement MAM (xep-0313)
- [X] DONE workaround for when user2 sends string while user1 is entering his string
- [X] DONE async read-write raw stanzas
- [X] DONE print some stuff to stderr (debug) -- created log_r() and log_w()
- [X] DONE implement current_GPG (xep-0027)

