# goblock

On-chain router. Program id: `4gZQouUvsDc4zEd3msfnw9or4uxtSBxZejoy6XcsGTPb`.

The `route` instruction (tag `0`) requires the signer in account 0, forwards each inner instruction to a whitelisted program, and logs `goblock:`.

Allowed programs: Token, Token-2022, Associated Token Account, Memo, Pump, PumpSwap, Raydium AMM v4, Raydium CLMM, Raydium CPMM, Meteora DLMM, and Orca Whirlpool.

Build with Solana CLI 4.3.0:

```
cargo build-sbf --manifest-path programs/goblock/Cargo.toml
```
