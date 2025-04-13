# Nats Hacker

## To listen on nats:

```bash
cargo run --bin listener -- -c local
```

## To publish to nats

### EdDSA

Create a eddsa key:

```bash
cargo run --bin publisher -- -c local -p wa -t ed -n 1,2,3,4,5
```

Create a eddsa signature:

```bash
cargo run --bin publisher -- -c local -p si -t ed -k 70f7329d-03f3-442a-9e18-90e94246585a -n 1,2,3
```

Regenerate keyfile:

```bash
cargo run --bin publisher -- -c local -p re -t ed -k 70f7329d-03f3-442a-9e18-90e94246585a -i 3 -n 1,2,5
```

### ECDSA

Create a ecdsa key:

```bash
cargo run --bin publisher -- -c local -p wa -t ec -n 1,2,3,4,5
```

Create a ecdsa signature:

```bash
cargo run --bin publisher -- -c local -p si -t ec -k ad1e2c85-1f4a-4b7f-9e67-f54cff0eaabc -n 1,2,5
```

Regenerate keyfile:

```bash
cargo run --bin publisher -- -c local -p re -t ec -k ad1e2c85-1f4a-4b7f-9e67-f54cff0eaabc -i 1 -n 2,3,4
```

### 2FA

Import:

```bash
cargo run --bin publisher -- -c local -p 2fa -f 12345678 -n 1,2,3,4,5 -o 4
```

Key regeneration for first (1 index) node. Delete key share file before recovery:

```bash
cargo run --bin publisher -- -c local -p re -t twofa -k a8bef03b-0657-4a36-959d-6609b0dd16d7 -i 1 -n 2,3,5
```

### Sr25519

Create a sr25519 key:

```bash
cargo run --bin publisher -- -c local -p wa -t sr -o 1 -n 1,2,3,4,5
```

Sign the default message with sr25519 and verify:

```bash
cargo run --bin publisher -- -c local -p si -t sr -k 051f8d85-4558-469f-82a1-4f3e53beef22 -o 1
```

Multi sign the default message with sr25519 with 2, 3, 5 node's private sr keys and verify:

```bash
cargo run --bin publisher -- -c local -p si -t msr -k 051f8d85-4558-469f-82a1-4f3e53beef22 -o 1 -n 2,3,5
```

Key regeneration for first (1 index) node. Delete key share file before recovery:

```bash
cargo run --bin publisher -- -c local -p re -t sr -k a8bef03b-0657-4a36-959d-6609b0dd16d7 -i 1 -n 2,3,5
```

### Customisable command:

```bash
cargo run --bin publisher -- -c local -p cust -o 1 -m '{ ... }'
```
