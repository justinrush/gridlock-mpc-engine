# NATS

## Nats Server Instances

There is a NATS server instance running on both staging and production:

```
nats://stagingnats.gridlock.network:4222
nats://app.gridlock.network:4222
```

These run via docker containers on the mvp servers at `stagingnats.gridlock.network` and `app.gridlock.network` which can be accessed by ssh. See [servers](servers.md).

## Configuration

The NATS servers can be configured via a file found at

```
~/mvp-data/nats/nats.cfg
```

on both staging and production.

Any changs to the configuration file can be loaded by sshing into using the command

```
nats-server --signal reload
```

## Nats authentcation

The configuration specified to authenticated permission levels `admin` and `node`.

`admin` has unlimited access to subscribe to and publish to any subject on NATS.

`node` can subscribe to any subject but is restricted from publishing to subjects that would allow it to initiate wallet generation, signing or keyshare regeneration.

The passwords for these authentication levels are found in the config file.
If the admin password is changed it will have to be updated for the nodejs backend which uses it to initiate nats sessions.
