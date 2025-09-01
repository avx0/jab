**WARNING**: Currently there is a **RCE bug** in jab. The code is in beta stage.

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
- [ ] rewrite in C
- [ ] implement OTR
- [ ] implement OMEMO
- [ ] add buddy list handling

## jab-v0.1 (beta stage)

- [ ] fix the RCE bug.
- [ ] make /list work. current workaround: open another jab connection, query server from there.
- [ ] test jab <---> jab on different machines/VMs
- [ ] add error handling to auth() (and last message verification) and other functions + make it work with popuar jabber services (yax.im works with default auth(), conversations.im doesn't)
- [ ] implement SCRAM-SHA-1-PLUS to prevent mitm (supposedly). read the rfc.
- [ ] make writing to conversations (openpgp) work

## jab-prototype (alpha stage)

- [X] jab (PGP+MAM) <--- anyPublicJabberServer <----> anyPublicJabberServer ----> jab (PGP+MAM)
- [X] --my-key and --recp-key flags
- [X] implement MAM (xep-0313)
- [X] workaround for when user2 sends string while user1 is entering his string
- [X] async read-write raw stanzas
- [X] print some stuff to stderr (debug) -- created log_r() and log_w()
- [X] implement current_GPG (xep-0027)

