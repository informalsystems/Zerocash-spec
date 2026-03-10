# Zerocash Formal Specification

A Quint specification of the Zerocash decentralized anonymous payment scheme from [Ben-Sasson et al., IEEE S&P 2014](zerocash-oakland2014.pdf). The spec models protocol-level security properties and demonstrates the **faerie gold attack** — where an attacker creates coins with duplicate serial numbers that appear valuable but are only partially spendable — alongside the Zcash Sapling fix that blocks it.

Both the original vulnerable protocol and the fix live side by side in `zerocash.qnt`, enabling direct comparison through invariant checking and attack demonstrations.

## Key Differences from the Paper

#### Modeling approach

- **Centralized ledger** instead of distributed blockchain — transactions are atomic state transitions with exact balance conservation at every step
- **Cryptographic abstractions** — PRF/COMM use list-encoded symbolic values instead of real hash functions (see trilemma below)
- **Explicit zk-SNARK verification** — SNARK checks separated into `verify_pour_snark` / `verify_pour_snark_fixed` with explicit `PourWitness` type
- **Simplified data structures** — Merkle trees modeled as `Set[Sym]` membership; encryption omitted

#### What's preserved

- Core protocol logic: Mint/Pour operations, coin structure, serial number uniqueness
- Serial numbers computed on-demand as `PRF_sn(ask, rho)` during spending (not stored in coins)
- Balance conservation and double-spend prevention
- Separation of public verification (`verify_pour_public`) vs. SNARK proofs (`verify_pour_snark`)

## Cryptographic Abstraction: The Symbolic Encoding Trilemma

Real Zerocash uses SHA-256-based PRFs and commitments that produce fixed-size 256-bit outputs with probabilistic collision resistance. A symbolic model with structural equality cannot express "distinct with overwhelming probability" — it must choose between three desirable properties, and **can only have two**:

| Pick two | Fixed-size output | Injectivity (no collisions) | No large-integer arithmetic |
|----------|:-:|:-:|:-:|
| **Cantor pairing** (int) | yes | yes | **no** — quadratic value growth with nesting depth |
| **List encoding** (List[int]) | **no** — O(2^depth) list growth in fixed variant | yes | yes |
| **Modular hash** (int mod M) | yes | **no** — birthday-bound collisions ~n^2/2M | yes |

### This spec's choice: List encoding

This spec uses `type Sym = List[int]` — each crypto function returns a flat integer list tagged by function identity:

| Tag | Function | Encoding |
|-----|----------|----------|
| 0 | `PRF_addr(ask, z)` | `[0, ask, z]` |
| 1 | `PRF_sn(ask, rho)` | `[1, ask, len(rho)].concat(rho)` |
| 2 | `COMM(r, msg)` | `[2, r, len(msg)].concat(msg)` |
| 3 | `derive_rho_vulnerable(ask, nc, idx)` | `[3, ask, nc+idx]` |
| 4 | `derive_rho_fixed(sn1, sn2, phi, idx)` | `[4, phi, len(sn1)].concat(sn1).concat(sn2).concat([idx])` |
| 5 | `sym_pair(a, b)` | `[5, len(a)].concat(a).concat(b)` |
| 6 | `sym_int(n)` | `[6, n]` |

Injectivity follows from: tags discriminate across functions, length prefixes disambiguate variable-length sub-arguments, and total list length equality forces all remaining elements to match. Cantor `pair()` is retained only for generating r/s randomness (leaf integers, no nesting).

### List growth in the fixed variant

In the vulnerable variant, `derive_rho_vulnerable` always returns a 3-element list — all crypto values stay constant-size (commitment length = 18 elements). In the fixed variant, `derive_rho_fixed` embeds both input serial numbers, and each serial number embeds its coin's rho. This creates a doubling chain:

| Pour generation | rho length | commitment length |
|----------------|-----------|-----------|
| 0 (mint) | 3 | 18 |
| 1 | 16 | 31 |
| 2 | 42 | 57 |
| 3 | 94 | 109 |
| 4 | 198 | 213 |

The recurrence is `rho(n) = 2 * rho(n-1) + 10`, giving `rho(n) = 13 * 2^n - 10`. **This growth is purely an artifact of symbolic simulation** — in the real protocol every crypto function produces a fixed-size 256-bit output. The list encoding must preserve the full input structure to guarantee injectivity, which is what causes the size to accumulate.

The worst case at `--max-steps=N` is generation N-2 (two mints then all pours chaining). At 20 steps that's generation 18, giving commitment lists of ~3.4 million elements. Whether long pour chains are realistic depends on how often shielded coins are deshielded (converted back to public balance) before being re-spent — deshielding resets the chain to generation 0. We don't have evidence on typical chain depths in real Zcash usage; the private transfers are hidden by design.

Benchmarks show the Rust backend handles 10,000 random traces at 20 steps in ~5 minutes at 33 traces/second. The random simulator rarely hits worst-case depth because most traces mix mints and pours across multiple users, but a pathological trace *can* blow up.

## Verification Structure

The spec separates **public verification** (what anyone can check from the ledger) from **SNARK verification** (what the zk-SNARK proves using private witness data).

### Public Verification (`verify_pour_public`)

Checks based on public transaction fields and ledger state:

- Serial numbers are fresh (not already spent)
- Serial numbers are distinct
- Old coin commitments exist on ledger
- New coin commitments are fresh

### SNARK Verification

Two variants, differing only in rho derivation.

**`verify_pour_snark`** — vulnerable (original Zerocash):

- Witness consistency: coins match public transaction
- Ownership: prover knows secret keys for old coins
- Value conservation: inputs = outputs + public value
- Non-negative values, commitment correctness
- **No rho constraint** — attacker can freely reuse rho across outputs

**`verify_pour_snark_fixed`** — fixed (Zcash Sapling):

- All of the above, plus a rho derivation constraint:
  each output rho must equal `derive_rho_fixed(sn_old_1, sn_old_2, phi, index)` for a private seed `phi` committed in the witness

`phi` is a private field of `PourWitness` — never revealed publicly.

## Faerie Gold Vulnerability & Zcash Fix

### The Vulnerability (original Zerocash)

The original Zerocash protocol is vulnerable to the **faerie gold attack**: an attacker can create multiple output coins with the same `rho` value, causing them to have identical serial numbers despite different values and commitments. The recipient's wallet shows two coins worth `v1 + v2`, but spending either one reveals the shared serial number, permanently burning the other.

#### Rho derivation (vulnerable)

```quint
pure def derive_rho_vulnerable(ask: int, nc: int, index: int): Sym =
    [3, ask, nc + index]
```

Honest usage picks `index = 0` and `index = 1` to get distinct rhos. But nothing in the SNARK prevents an attacker from using `index = 0` for both outputs, producing identical rhos:

```quint
val rho_new_1 = derive_rho_vulnerable(ask, nc, 0)  // honest
val rho_new_2 = derive_rho_vulnerable(ask, nc, 0)  // reused — same serial number!
```

Result: victim receives coins with total value `v1 + v2`, but can only spend value `max(v1, v2)`. See the `faerieGoldTest` and `faerieGoldSpendCascadeTest` tests.

### The Fix (Zcash Sapling)

Following [Zcash's mitigation](https://github.com/zcash/zcash/issues/98), the fixed variant enforces **two-step deterministic rho derivation** inside the SNARK.

#### Step 1 — derive transaction identifier from input nullifiers

```quint
val hSig = sym_pair(sn_old_1, sn_old_2)   // unique: nullifiers can't repeat
```

#### Step 2 — derive rho from hSig + private seed phi

```quint
pure def derive_rho_fixed(sn1: Sym, sn2: Sym, phi: int, index: int): Sym =
    [4, phi, sn1.length()].concat(sn1).concat(sn2).concat([index])
```

#### SNARK enforcement (`verify_pour_snark_fixed`)

```quint
val expected_rho_new_1 = derive_rho_fixed(tx.sn_old_1, tx.sn_old_2, witness.phi, 0)
val expected_rho_new_2 = derive_rho_fixed(tx.sn_old_1, tx.sn_old_2, witness.phi, 1)
// Both must match:
witness.c_new_1.rho == expected_rho_new_1
witness.c_new_2.rho == expected_rho_new_2
```

#### Why the attack is blocked

The attack requires `coin1.rho == coin2.rho`. The fixed SNARK requires:

- `coin1.rho = derive_rho_fixed(..., 0)` ending with `[..., 0]`
- `coin2.rho = derive_rho_fixed(..., 1)` ending with `[..., 1]`

By the list encoding's injectivity, the trailing element always differs: `[..., 0] != [..., 1]` for any choice of `phi`. No `phi` can satisfy both constraints simultaneously — the attack is structurally impossible.

**Note on asymmetry:** The fix applies only to Pour. Mint transactions don't need it because users create coins for themselves — any duplicate rho only hurts the creator, not a victim.

## Spec Structure

### Actions

| Action                    | Variant    | Description |
| ------------------------- | ---------- | ----------- |
| `mint`                    | shared     | Convert basecoin to private coin |
| `pour`                    | vulnerable | Two-input, two-output private transfer; uses `derive_rho_vulnerable` and `verify_pour_snark` |
| `pour_fixed`              | fixed      | Same structure; uses `derive_rho_fixed` and `verify_pour_snark_fixed` |
| `step`                    | vulnerable | Honest nondeterministic step: `mint` or `pour` |
| `step_fixed`              | fixed      | Honest nondeterministic step: `mint` or `pour_fixed` |
| `faerie_gold_pour`        | vulnerable | Byzantine pour with duplicate rho; goes through full validation pipeline; succeeds because the vulnerable SNARK has no rho constraint |
| `faerie_gold_pour_fixed`  | fixed      | Same attack attempt; goes through full validation pipeline; always disabled — SNARK rejects duplicate rho |
| `faerie_gold_step`        | vulnerable | `step` + `faerie_gold_pour`; demonstrates the attack |
| `faerie_gold_step_fixed`  | fixed      | `step_fixed` + `faerie_gold_pour_fixed`; demonstrates attack is blocked |

**Design note:** Byzantine actions always go through the same ledger validation as honest actions — they cannot bypass `verify_pour_public` or the SNARK check. The only difference is how rho is constructed before submitting to the pipeline.

### Invariants

The spec's invariants are organized around two security properties from the paper: **Completeness** and **Balance**.

#### Completeness (Definition III.1)

The paper defines completeness as: if `c1` and `c2` are two coins whose commitments appear on the ledger but their serial numbers do not, then `c1` and `c2` have different serial numbers — so Pour can always be run on any eligible pair.

The **`completeness`** invariant encodes this directly: for each user, all eligible coins (commitment on ledger, sn not on spent list) have distinct serial numbers. It is defined as `NODES.forall(u => user_completeness(u))`, where `user_completeness` checks per-user eligible-coin distinctness. Cross-user sn collisions are impossible by PRF injectivity (distinct `ask` values produce distinct serial numbers).

This invariant captures the faerie gold attack: the attack creates two coins with the same rho, hence the same serial number. Both are eligible (commitment on ledger, sn not yet spent), so `completeness` is violated.

The invariant checks preconditions for completeness — that eligible pairs with distinct sns exist. It doesn't directly assert that running `pour` on such a pair produces a valid transaction with receivable outputs. That stronger property is covered by `completenessTest` and by the simulation itself, which runs `pour` on nondeterministic choices without failure across thousands of traces.

#### Balance (Section III-C)

The paper defines balance as: no adversary can spend or hold more value than they minted or received from others. Formally, the adversary wins if `vUnspent + vBasecoin + vA→ADDR > vMint + vADDR→A`. This is a *per-adversary cumulative* property tracking one party's total inputs vs outputs across all transactions.

Two invariants and one per-transaction check contribute to this:

- **`balance_conservation`** — `total_public + total_private == TOTAL_INITIAL`. Global conservation: value is neither created nor destroyed.
- **`no_negative_balances`** — no user has negative public balance, bounding per-user value extraction.
- **Per-transaction value conservation** (SNARK check 3 in `verify_pour_snark`): `old_1.value + old_2.value == new_1.value + new_2.value + v_pub`. Combined with `verify_mint` checking `user_balance >= value`, no single transaction creates value from nothing.

**The gap:** the paper's Balance is per-adversary and cumulative, requiring tracking one party's total inputs vs outputs across the full trace. Our state records only current snapshots (wallets, balances), not per-user transaction history. The combination of per-transaction conservation + global `balance_conservation` + `no_negative_balances` gives an indirect argument: if every transaction preserves value, the total is fixed, and nobody goes negative, then no party can end up with more than they started with plus what others sent them. This is sound but it is an *argument about the invariants*, not a single invariant that directly captures the paper's definition. A direct per-user balance invariant would require cumulative accounting ghost variables.

#### Summary

| Invariant               | Property | Description |
| ----------------------- | -------- | ----------- |
| `completeness`          | Completeness | All eligible coins have distinct serial numbers |
| `balance_conservation`  | Balance | Total public + private = initial supply |
| `no_negative_balances`  | Balance | No user has negative public balance |

#### Behavior under attack

| Invariant | Honest step | Faerie gold (vulnerable) | Faerie gold (fixed) |
|-----------|:-:|:-:|:-:|
| `completeness` | holds | **violated** | holds |
| `balance_conservation` | holds | holds | holds |
| `no_negative_balances` | holds | holds | holds |

The faerie gold attack violates `completeness` immediately (duplicate-sn eligible coins). Balance invariants survive — value is neither created nor destroyed, just made partially unspendable.

### Tests

| Test                        | Description |
| --------------------------- | ----------- |
| `fullCycleTest`             | Mint, pour, spend cycle with balance conservation |
| `completenessTest`          | Pour is enabled when two eligible coins exist |
| `faerieGoldTest`            | Demonstrates the attack: victim holds two coins, only one spendable |
| `faerieGoldSpendCascadeTest`| Spending one faerie gold coin permanently burns the other |

## Running the Spec

```bash
# Typecheck
quint typecheck zerocash.qnt

# Run all tests (should all pass)
quint test zerocash.qnt
```

### Invariant Checking

Vulnerable variant — honest step, all invariants hold:

```bash
quint run --invariant=completeness --step=step zerocash.qnt --max-steps=20
quint run --invariant=balance_conservation --step=step zerocash.qnt --max-steps=20
```

Vulnerable variant — faerie gold step, attack detected (completeness violated):

```bash
quint run --invariant=completeness --step=faerie_gold_step zerocash.qnt
# Expected: [violation] Found an issue
```

Fixed variant — faerie gold step, attack blocked (no violation found):

```bash
quint run --invariant=completeness --step=faerie_gold_step_fixed zerocash.qnt --max-steps=20
# Expected: [ok] No violation found
```

### Using the Rust Backend

The Rust backend is recommended for deeper simulation (10,000+ samples):

```bash
quint run --invariant=completeness --step=faerie_gold_step_fixed \
  --max-samples=10000 --max-steps=20 --backend=rust zerocash.qnt
# ~5 minutes, ~33 traces/second
```

### Checking All Invariants

```bash
# Vulnerable + honest: all 3 invariants should hold
quint run --invariants=completeness balance_conservation no_negative_balances \ 
  --step=step zerocash.qnt --max-steps=20

# Fixed + faerie gold step: all 3 invariants should hold (attack always blocked)
quint run --invariants=completeness balance_conservation no_negative_balances \
  --step=faerie_gold_step_fixed --backend=rust --max-samples=10000 --max-steps=20 zerocash.qnt
```
