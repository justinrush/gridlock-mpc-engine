# MVP backend

The backend is written in Rust and split into five crates.
This serves to minimise the amount of dependencies pulled in by the code,
speeding up builds and allowing to perform "partial" builds (i.e. it is not
needed to install all of communication-hub's dependencies to build the node,
and vice versa).

## `message-logging`

The message logger is a small helper program which runs on our infrastructure
and collects all the messages sent to NATS (both "Resgate", and the "nodes"
NATS instances). This includes all messages exchanged between:

- the frontend and the communication hub,
- the communication hub and the nodes,
- the nodes themselves (as of now, they don't communicate in a P2P fashion)

The messages are stored in a file saved locally, and uploaded to
a back-up location - an AWS S3 bucket - once a month. Note that files
are **never** removed by the program itself. Thus, if you see yourself
running out of disk space, it may be a good idea to manually remove
some old log files.

## `node`

The node is the heart of Gridlock technology. It is responsible for
generating keys (wallets), and well as signing messages (transactions).

The code found in this directory has a twofold purpose,
as it powers both the Gridlock Nodes running on our infrastructure,
and the Guardian Nodes running on end-users' devices.

The Guardian Nodes behave slightly differently to Gridlock Nodes.
By default, running `cargo build` produces a Gridlock Node.
Look into `node/android` and `node/ios` on instructions on how to build
the Guardian library for mobile platforms.

## `shared`

This crate serves mostly to store definitions of messages exchanged
by the communication hub and the nodes. It also contains some
commonly-used helper functions.
