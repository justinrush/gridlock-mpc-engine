# Debugging & Logging

## Production & Staging

1. ensure you have access to the Production and Staging Instances on AWS.
   [how to ssh into an AWS instance](https://app.clickup.com/8460781/docs/826fd-568/826fd-3095)
   contact your admin
2. ssh into the relevant instance:

###### staging

```bash
ssh ubuntu@staging.gridlock.network
```

###### Production

```bash
ssh ubuntu@app.gridlock.network
```

There are multiple sources of information depending on what it is you're looking for.

### Container Logs

To get logs for a service enter the following:

```bash
docker-compose logs <Service Name>
```

this will give the logs (if there are any) for the requested container
logs are created from the stdout & stderr outputs of applications running on the container

### Nats Messaging

###### Historical logs

nats messages are currently listened to and collected by `mvp/backend/message-logging/` & stored on S3 once a month
[here](https://s3.console.aws.amazon.com/s3/buckets/gridlocklogs?region=eu-west-2&tab=objects).

###### Current Logs

The current log file can be accessed by looking into `STORAGE_DIR/message-logging/.` The `STORAGE_DIR` value is configured through the `.env` file;

on both production and staging, it is set to `~/mvp-data`

One can then view the logs through less, e.g.

simply view the file:

```bash
less ~/mvp-data/message-logging/nats-2021-06
```

watch the file as new rows are appended:

```bash
less -F ~/mvp-data/message-logging/nats-2021-06
```

filter the file for events:

```bash
grep -A 1 -e 'PATTERN_TO_MATCH' ~/mvp-data/message-logging/nats-2021-06
```

### Infura

Infura currently hosts our connection to the Ethereum Network.
Access credentials found on OnePassword
You can monitor which/how many transactions we are currently sending to the blockchain network from [here](https://infura.io/dashboard/ethereum/eb55644d4d5f41f89db30d861e6e1247/stats)
