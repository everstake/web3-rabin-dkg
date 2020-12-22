# Distributed Key Generation library in Rust

**Repository under development, don't use in production !**

This repo implements Rabin's DKG protocol for you to have more confidence when holding your assets jointly.

DKG enables a group of participants to generate a distributed private key with each participant holding only a share of the key. The key is also never computed locally but generated distributively whereas the public part of the key is known by every participants.
The underlying basis for this protocol is the VSS protocol.

In general procedure will look like this:
 1. All participants generate their own private and public keys;
 2. All participants broadcast their public keys, so that everyone has the list of all the participants public keys;
 3. Users start to generate general distributed secret key by broadcasting commitments and responses;
 4. When general secret is generated and everyone has the public key of secret, users can create multisig transaction.

## Getting started

See the examples folder to get started and learn what can be done with the library.
