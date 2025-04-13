use anyhow::{ anyhow, Result };
use curv::arithmetic::Zero;
use curv::BigInt;
use paillier::EncryptionKey;

/// Check paillier public key for small prime factors (<2^16).
/// Security issue: CVE-2023-33241
///
/// https://www.fireblocks.com/press/fireblocks-researchers-uncover-vulnerabilities-impacting-dozens-of-major-wallet-providers
pub fn check_for_small_primes(ek: &EncryptionKey) -> Result<()> {
    let num = &ek.n;
    for i in get_primes() {
        if num % BigInt::from(i) == BigInt::zero() {
            return Err(
                anyhow!(
                    "Check for small prime factors hasn`t passed! - Security issue: CVE-2023-33241"
                )
            );
        }
    }
    Ok(())
}

const MAX_PRIME: usize = 65536;
const PRIMES_COUNT: usize = 6542;
const PRIMES: [u16; PRIMES_COUNT] = get_primes();

/// Get all primes below 2^16 using sieve of eratosthenes in compile time
const fn get_primes() -> [u16; PRIMES_COUNT] {
    let mut primes = [0u16; PRIMES_COUNT];
    let mut is_prime = [true; MAX_PRIME];

    let mut num = 2;
    let mut prime_id = 0;
    while num < MAX_PRIME {
        if is_prime[num] {
            primes[prime_id] = num as u16;
            prime_id += 1;

            let mut multiple = num * num;
            while multiple < MAX_PRIME {
                is_prime[multiple] = false;
                multiple += num;
            }
        }
        num += 1;
    }
    primes
}
