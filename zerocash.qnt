// -*- mode: Bluespec; -*-
/**
 * Zerocash: List-encoded Specification — Vulnerable + Faerie-Gold-Resistant
 * Based on: zerocash-oakland2014.pdf (Ben-Sasson et al., IEEE S&P 2014)
 *
 * Each crypto function encodes its tag + arguments as a flat integer list.
 * Equality is structural (list comparison) — no multiplication, no BigInt.
 * The Cantor pair() function is retained ONLY for generating small integer
 * randomness (r, s fields), which remain as plain int.
 *
 *   pour      / step       — original Zerocash (vulnerable to faerie gold)
 *   pour_fixed / step_fixed — Zcash Sapling fix (two-step rho derivation)
 *
 * Encoding scheme (tag = first list element):
 *   Tag 0: PRF_addr(ask, z)                   → [0, ask, z]
 *   Tag 1: PRF_sn(ask, rho)                   → [1, ask, len(rho)] ++ rho
 *   Tag 2: COMM(r, msg)                       → [2, r, len(msg)] ++ msg
 *   Tag 3: derive_rho_vulnerable(ask, nc, idx) → [3, ask, nc+idx]
 *   Tag 4: derive_rho_fixed(sn1, sn2, phi, idx) → [4, phi, len(sn1)] ++ sn1 ++ sn2 ++ [idx]
 *   Tag 5: sym_pair(a, b)                     → [5, len(a)] ++ a ++ b
 *   Tag 6: sym_int(n)                         → [6, n]
 *
 * Injectivity: tags discriminate cross-function; length prefixes disambiguate
 * variable-length Sym sub-arguments; total list length equality forces
 * all remaining sub-args to match element-wise.
 */
module zerocash{

  // ===========================================================================
  // 1. SYMBOLIC TYPE AND ABSTRACT CRYPTOGRAPHIC PRIMITIVES
  // ===========================================================================

  /// Symbolic crypto value — replaces int-via-Cantor-pairing.
  /// Two Sym values are equal iff their lists are equal (structural comparison).
  type Sym = List[int]

  /// Wrap a plain int as a Sym value (used for coin values in commitments).
  pure def sym_int(n: int): Sym = [6, n]

  /// Pair two Sym values into a single Sym (replaces pair(a, b) for crypto args).
  /// Length prefix on `a` ensures unambiguous delimiting.
  pure def sym_pair(a: Sym, b: Sym): Sym =
    [5, a.length()].concat(a).concat(b)

  /// Cantor pairing — retained ONLY for generating small integer randomness
  /// (r, s fields of Coin). These are leaf values, so no nesting occurs.
  pure def pair(a: int, b: int): int = {
    val s = a + b
    (s * (s + 1)) / 2 + b
  }

  /// PRF_addr(ask, z) — derives address public key from secret key
  /// Paper: PRF_addr_x(z) = H(x || 00 || z)
  pure def PRF_addr(ask: int, z: int): Sym = [0, ask, z]

  /// PRF_sn(ask, rho) — derives serial number from secret key and coin nonce
  /// Paper: PRF_sn_x(z) = H(x || 01 || z)
  pure def PRF_sn(ask: int, rho: Sym): Sym =
    [1, ask, rho.length()].concat(rho)

  /// COMM_r(msg) — statistically hiding commitment
  /// Paper: k = COMM_r(apk || rho), cm = COMM_s(v || k)
  pure def COMM(randomness: int, msg: Sym): Sym =
    [2, randomness, msg.length()].concat(msg)

  /// Rho derivation — VULNERABLE Zerocash spec (original protocol).
  /// rho depends only on the sender's nonce counter. The transaction creator
  /// can freely reuse the same nonce for both outputs, enabling the faerie gold
  /// attack. The vulnerable SNARK places no constraint on rho.
  pure def derive_rho_vulnerable(ask: int, nc: int, index: int): Sym =
    [3, ask, nc + index]

  /// Rho derivation — FIXED spec (Zcash Sapling two-step approach).
  /// Step 1: hSig = H(sn_old_1, sn_old_2)  — transaction-unique identifier
  /// Step 2: rho  = PRF_ρ^ϕ(hSig)          — output nonce from hSig + private phi
  /// Key property: hSig is unique (input nullifiers are unique), so rho is unique
  /// even if phi is adversarially chosen.
  pure def derive_rho_fixed(sn1: Sym, sn2: Sym, phi: int, index: int): Sym =
    [4, phi, sn1.length()].concat(sn1).concat(sn2).concat([index])

  // ===========================================================================
  // 2. ADDRESS & COIN TYPES
  // ===========================================================================

  /// Address secret key — the PRF seed. Each user has one.
  type AddrSk = int

  /// Address public key — derived deterministically from ask.
  type AddrPk = Sym

  /// Full address key pair as described in CreateAddress (Section III-B).
  type AddressKeyPair = {
    ask: AddrSk,
    apk: AddrPk,
  }

  /// Derive a key pair from a secret key.
  pure def create_address(ask: AddrSk): AddressKeyPair = {
    { ask: ask, apk: PRF_addr(ask, 0) }
  }

  /// Coin value in base units. Paper: v in {0, ..., vmax}.
  type CoinValue = int
  pure val MAX_VALUE = 100

  /// A coin as held by its owner (private knowledge).
  /// Paper Section III-A: c = (addrpk, v, rho, r, s, cm)
  /// Crypto-derived fields are Sym (List[int]); value and randomness are int.
  type Coin = {
    apk: AddrPk,        // owner's address public key
    value: CoinValue,    // v — coin denomination
    rho: Sym,            // PRF_sn nonce — unique per coin
    r: int,              // COMM randomness for k
    s: int,              // COMM randomness for cm
    k: Sym,              // intermediate commitment: COMM_r(apk || rho)
    cm: Sym,             // coin commitment: COMM_s(v || k)
  }

  /// Mint a new coin given owner's keys, a value, and fresh randomness.
  /// Paper Section IV-C, Mint algorithm.
  pure def mint_coin(
    addr: AddressKeyPair,
    value: CoinValue,
    rho: Sym,
    r: int,
    s: int
  ): Coin = {
    val k = COMM(r, sym_pair(addr.apk, rho))
    val cm = COMM(s, sym_pair(sym_int(value), k))
    {
      apk: addr.apk,
      value: value,
      rho: rho,
      r: r,
      s: s,
      k: k,
      cm: cm,
    }
  }

  /// Compute the serial number for a coin given the owner's secret key.
  /// Paper: sn = PRF_sn(ask, rho)
  pure def compute_sn(ask: AddrSk, coin: Coin): Sym = {
    PRF_sn(ask, coin.rho)
  }

  // ===========================================================================
  // 2.5. TRANSACTION TYPES (PUBLIC FIELDS ONLY)
  // ===========================================================================

  /// Public fields of a Mint transaction.
  /// Paper Section IV-C: txMint = (cm, v, k, s)
  type MintTx = {
    cm: Sym,           // coin commitment
    v: CoinValue,      // coin value
    k: Sym,            // intermediate commitment
    s: int,            // randomness for cm
  }

  /// Public fields of a Pour transaction.
  /// Paper Section IV-C: txPour = (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, v_pub, info, C)
  type PourTx = {
    sn_old_1: Sym,     // serial number of first old coin
    sn_old_2: Sym,     // serial number of second old coin
    cm_old_1: Sym,     // commitment of first old coin (simplified)
    cm_old_2: Sym,     // commitment of second old coin (simplified)
    cm_new_1: Sym,     // commitment of first new coin
    cm_new_2: Sym,     // commitment of second new coin
    v_pub: int,        // public output value
  }

  /// Private witness for a Pour transaction.
  /// Paper Section IV-C: This is what the zk-SNARK proves knowledge of.
  type PourWitness = {
    c_old_1: Coin,     // first old coin (with all private fields)
    c_old_2: Coin,     // second old coin (with all private fields)
    ask_old_1: AddrSk, // secret key for first old coin
    ask_old_2: AddrSk, // secret key for second old coin
    c_new_1: Coin,     // first new coin (with all private fields)
    c_new_2: Coin,     // second new coin (with all private fields)
    phi: int,          // random seed for rho derivation (unchecked in vulnerable SNARK)
  }

  // ===========================================================================
  // 2.6. TRANSACTION VERIFICATION
  // ===========================================================================

  /// Verify a Mint transaction.
  pure def verify_mint(
    user: Node,
    tx: MintTx,
    commitments: Set[Sym],
    public_balance: Node -> int,
  ): bool = {
    val user_balance = public_balance.get(user)
    val expected_cm = COMM(tx.s, sym_pair(sym_int(tx.v), tx.k))
    all {
      tx.v > 0,
      tx.v <= MAX_VALUE,
      user_balance >= tx.v,
      not(commitments.contains(tx.cm)),
      tx.cm == expected_cm,
    }
  }

  /// Verify a Pour transaction - PUBLIC checks.
  pure def verify_pour_public(
    tx: PourTx,
    commitments: Set[Sym],
    serial_numbers: Set[Sym],
  ): bool = {
    all {
      commitments.contains(tx.cm_old_1),
      commitments.contains(tx.cm_old_2),
      not(serial_numbers.contains(tx.sn_old_1)),
      not(serial_numbers.contains(tx.sn_old_2)),
      tx.sn_old_1 != tx.sn_old_2,
      not(commitments.contains(tx.cm_new_1)),
      not(commitments.contains(tx.cm_new_2)),
    }
  }

  /// Verify a Pour transaction - SNARK checks (VULNERABLE version).
  /// VULNERABILITY: does NOT constrain how rho is derived.
  pure def verify_pour_snark(
    tx: PourTx,
    witness: PourWitness,
  ): bool = {
    val sn1 = compute_sn(witness.ask_old_1, witness.c_old_1)
    val sn2 = compute_sn(witness.ask_old_2, witness.c_old_2)
    val expected_k_new_1 = COMM(witness.c_new_1.r, sym_pair(witness.c_new_1.apk, witness.c_new_1.rho))
    val expected_cm_new_1 = COMM(witness.c_new_1.s, sym_pair(sym_int(witness.c_new_1.value), witness.c_new_1.k))
    val expected_k_new_2 = COMM(witness.c_new_2.r, sym_pair(witness.c_new_2.apk, witness.c_new_2.rho))
    val expected_cm_new_2 = COMM(witness.c_new_2.s, sym_pair(sym_int(witness.c_new_2.value), witness.c_new_2.k))

    all {
      // 1. Witness consistency: old coins match public serial numbers
      sn1 == tx.sn_old_1,
      sn2 == tx.sn_old_2,
      witness.c_old_1.cm == tx.cm_old_1,
      witness.c_old_2.cm == tx.cm_old_2,

      // 1. Witness consistency: new coins match public commitments
      witness.c_new_1.cm == tx.cm_new_1,
      witness.c_new_2.cm == tx.cm_new_2,

      // 2. Ownership: secret keys match old coin public keys
      PRF_addr(witness.ask_old_1, 0) == witness.c_old_1.apk,
      PRF_addr(witness.ask_old_2, 0) == witness.c_old_2.apk,

      // 3. Value conservation
      witness.c_old_1.value + witness.c_old_2.value ==
        witness.c_new_1.value + witness.c_new_2.value + tx.v_pub,

      // 4. Non-negative values
      witness.c_old_1.value >= 0,
      witness.c_old_2.value >= 0,
      witness.c_new_1.value >= 0,
      witness.c_new_2.value >= 0,
      tx.v_pub >= 0,

      // 5. Commitment correctness for new coins
      witness.c_new_1.k == expected_k_new_1,
      witness.c_new_1.cm == expected_cm_new_1,
      witness.c_new_2.k == expected_k_new_2,
      witness.c_new_2.cm == expected_cm_new_2,

      // NOTE: rho derivation is NOT checked here — this is the vulnerability.
    }
  }

  /// Verify a Pour transaction - SNARK checks (FIXED version, Zcash Sapling).
  /// Same as verify_pour_snark plus check 6:
  /// 6. Rho derivation constraint (Zcash fix):
  ///    rho = derive_rho_fixed(sn_old_1, sn_old_2, witness.phi, index)
  pure def verify_pour_snark_fixed(
    tx: PourTx,
    witness: PourWitness,
  ): bool = {
    val sn1 = compute_sn(witness.ask_old_1, witness.c_old_1)
    val sn2 = compute_sn(witness.ask_old_2, witness.c_old_2)
    val expected_k_new_1 = COMM(witness.c_new_1.r, sym_pair(witness.c_new_1.apk, witness.c_new_1.rho))
    val expected_cm_new_1 = COMM(witness.c_new_1.s, sym_pair(sym_int(witness.c_new_1.value), witness.c_new_1.k))
    val expected_k_new_2 = COMM(witness.c_new_2.r, sym_pair(witness.c_new_2.apk, witness.c_new_2.rho))
    val expected_cm_new_2 = COMM(witness.c_new_2.s, sym_pair(sym_int(witness.c_new_2.value), witness.c_new_2.k))

    // 6. ZCASH FIX: Two-step rho derivation
    val expected_rho_new_1 = derive_rho_fixed(tx.sn_old_1, tx.sn_old_2, witness.phi, 0)
    val expected_rho_new_2 = derive_rho_fixed(tx.sn_old_1, tx.sn_old_2, witness.phi, 1)

    all {
      // 1. Witness consistency: old coins match public serial numbers
      sn1 == tx.sn_old_1,
      sn2 == tx.sn_old_2,
      witness.c_old_1.cm == tx.cm_old_1,
      witness.c_old_2.cm == tx.cm_old_2,

      // 1. Witness consistency: new coins match public commitments
      witness.c_new_1.cm == tx.cm_new_1,
      witness.c_new_2.cm == tx.cm_new_2,

      // 2. Ownership: secret keys match old coin public keys
      PRF_addr(witness.ask_old_1, 0) == witness.c_old_1.apk,
      PRF_addr(witness.ask_old_2, 0) == witness.c_old_2.apk,

      // 3. Value conservation
      witness.c_old_1.value + witness.c_old_2.value ==
        witness.c_new_1.value + witness.c_new_2.value + tx.v_pub,

      // 4. Non-negative values
      witness.c_old_1.value >= 0,
      witness.c_old_2.value >= 0,
      witness.c_new_1.value >= 0,
      witness.c_new_2.value >= 0,
      tx.v_pub >= 0,

      // 5. Commitment correctness for new coins
      witness.c_new_1.k == expected_k_new_1,
      witness.c_new_1.cm == expected_cm_new_1,
      witness.c_new_2.k == expected_k_new_2,
      witness.c_new_2.cm == expected_cm_new_2,

      // 6. ZCASH FIX: rho derivation constraint
      witness.c_new_1.rho == expected_rho_new_1,
      witness.c_new_2.rho == expected_rho_new_2,
    }
  }

  // ===========================================================================
  // 3. PROTOCOL TYPES
  // ===========================================================================

  type Node = str

  /// Parameters for a Pour operation.
  type PourChoice = {
    c1: Coin,           // first old coin to consume
    c2: Coin,           // second old coin to consume
    to1: Node,          // recipient of first new coin
    to2: Node,          // recipient of second new coin
    v1: CoinValue,      // value of first new coin
    vpub: CoinValue,    // public value output
  }

  // ===========================================================================
  // 4. STATE
  // ===========================================================================

  var ledger: {
    commitments: Set[Sym],          // global CMList
    serial_numbers: Set[Sym],       // global SNList
    public_balance: Node -> int,    // basecoin balances
  }

  var users: {
    wallets: Node -> Set[Coin],     // per-user private coin sets
    nonce_counters: Node -> int,    // per-user randomness counters
  }

  // ===========================================================================
  // 5. CONFIGURATION
  // ===========================================================================

  pure val NODES = Set("alice", "bob", "charlie")

  pure val INITIAL_BALANCE = 10

  pure val SECRET_KEYS: Node -> AddrSk = Map(
    "alice"   -> 100,
    "bob"     -> 200,
    "charlie" -> 300,
  )

  pure val KEY_PAIRS: Node -> AddressKeyPair = Map(
    "alice"   -> create_address(100),
    "bob"     -> create_address(200),
    "charlie" -> create_address(300),
  )

  pure val TOTAL_INITIAL = NODES.size() * INITIAL_BALANCE

  // ===========================================================================
  // 6. INITIALIZATION
  // ===========================================================================

  action init = all {
    ledger' = {
      commitments: Set(),
      serial_numbers: Set(),
      public_balance: NODES.mapBy(u => INITIAL_BALANCE),
    },
    users' = {
      wallets: NODES.mapBy(u => Set()),
      nonce_counters: NODES.mapBy(u => 0),
    },
  }

  // ===========================================================================
  // 7. HONEST ACTIONS
  // ===========================================================================

  /// Atomic mint transaction: user converts basecoin to a private coin.
  action mint(user: Node, value: CoinValue): bool = {
    val my_addr = KEY_PAIRS.get(user)
    val ask = SECRET_KEYS.get(user)
    val nc = users.nonce_counters.get(user)

    // Fresh randomness: rho is Sym, r/s are leaf ints via Cantor pairing
    val base = pair(ask, nc)
    val rho = derive_rho_vulnerable(ask, nc, 0)
    val r = pair(base, 1)
    val s_rand = pair(base, 2)

    val coin = mint_coin(my_addr, value, rho, r, s_rand)

    val tx: MintTx = {
      cm: coin.cm,
      v: value,
      k: coin.k,
      s: coin.s,
    }

    val is_valid = verify_mint(user, tx, ledger.commitments, ledger.public_balance)

    all {
      is_valid,

      ledger' = {
        ...ledger,
        commitments: ledger.commitments.union(Set(coin.cm)),
        public_balance: ledger.public_balance.setBy(user, bal => bal - value),
      },
      users' = {
        ...users,
        wallets: users.wallets.setBy(user, w => w.union(Set(coin))),
        nonce_counters: users.nonce_counters.setBy(user, n => n + 1),
      },
    }
  }

  /// Helper: enumerate all value splits and recipient pairs for a given coin pair.
  pure def pour_choices_for_pair(c1: Coin, c2: Coin): Set[PourChoice] = {
    val total = c1.value + c2.value
    val value_splits = 0.to(total).map(v1 =>
      0.to(total - v1).map(vpub => (v1, vpub))
    ).flatten()
    val recipient_pairs = NODES.map(to1 =>
      NODES.map(to2 => (to1, to2))
    ).flatten()
    value_splits.map(vs =>
      recipient_pairs.map(rp =>
        { c1: c1, c2: c2, to1: rp._1, to2: rp._2, v1: vs._1, vpub: vs._2 }
      )
    ).flatten()
  }

  /// Atomic pour transaction — VULNERABLE variant.
  action pour(user: Node, choice: PourChoice): bool = {
    val ask = SECRET_KEYS.get(user)
    val nc = users.nonce_counters.get(user)
    val my_wallet = users.wallets.get(user)
    val total = choice.c1.value + choice.c2.value
    val v2 = total - choice.v1 - choice.vpub

    val sn1 = compute_sn(ask, choice.c1)
    val sn2 = compute_sn(ask, choice.c2)

    // Derive rho for output coins using vulnerable approach
    val base1 = pair(ask, nc)
    val base2 = pair(ask, nc + 1)
    val rho_new_1 = derive_rho_vulnerable(ask, nc, 0)
    val rho_new_2 = derive_rho_vulnerable(ask, nc, 1)
    val addr1 = KEY_PAIRS.get(choice.to1)
    val coin1 = mint_coin(addr1, choice.v1, rho_new_1, pair(base1, 1), pair(base1, 2))
    val addr2 = KEY_PAIRS.get(choice.to2)
    val coin2 = mint_coin(addr2, v2, rho_new_2, pair(base2, 1), pair(base2, 2))

    val tx: PourTx = {
      sn_old_1: sn1,
      sn_old_2: sn2,
      cm_old_1: choice.c1.cm,
      cm_old_2: choice.c2.cm,
      cm_new_1: coin1.cm,
      cm_new_2: coin2.cm,
      v_pub: choice.vpub,
    }

    val witness: PourWitness = {
      c_old_1: choice.c1,
      c_old_2: choice.c2,
      ask_old_1: ask,
      ask_old_2: ask,
      c_new_1: coin1,
      c_new_2: coin2,
      phi: 0,
    }

    val is_valid = all {
      verify_pour_public(tx, ledger.commitments, ledger.serial_numbers),
      verify_pour_snark(tx, witness),
      my_wallet.contains(choice.c1),
      my_wallet.contains(choice.c2),
      choice.c1 != choice.c2,
    }

    all {
      is_valid,

      ledger' = {
        ...ledger,
        serial_numbers: ledger.serial_numbers.union(Set(sn1, sn2)),
        commitments: ledger.commitments.union(Set(coin1.cm, coin2.cm)),
        public_balance: ledger.public_balance.setBy(user, bal => bal + choice.vpub),
      },
      users' = {
        ...users,
        wallets: users.wallets
          .setBy(user, w => w.exclude(Set(choice.c1, choice.c2)))
          .setBy(choice.to1, w => w.union(Set(coin1)))
          .setBy(choice.to2, w => w.union(Set(coin2))),
        nonce_counters: users.nonce_counters.setBy(user, n => n + 2),
      },
    }
  }

  /// Atomic pour transaction — FIXED variant (Zcash Sapling).
  action pour_fixed(user: Node, choice: PourChoice): bool = {
    val ask = SECRET_KEYS.get(user)
    val nc = users.nonce_counters.get(user)
    val my_wallet = users.wallets.get(user)
    val total = choice.c1.value + choice.c2.value
    val v2 = total - choice.v1 - choice.vpub

    val sn1 = compute_sn(ask, choice.c1)
    val sn2 = compute_sn(ask, choice.c2)

    // ZCASH FIX: private random seed phi, derived from nonce counter.
    val phi = pair(ask, nc)

    // Two-step rho derivation (Zcash Sapling approach)
    val rho_new_1 = derive_rho_fixed(sn1, sn2, phi, 0)
    val rho_new_2 = derive_rho_fixed(sn1, sn2, phi, 1)

    // Other randomness (r, s) from nonce counter
    val base_rand = pair(ask, nc + 1)
    val r_new_1 = pair(base_rand, 0)
    val r_new_2 = pair(base_rand, 1)
    val s_new_1 = pair(base_rand, 2)
    val s_new_2 = pair(base_rand, 3)

    val addr1 = KEY_PAIRS.get(choice.to1)
    val coin1 = mint_coin(addr1, choice.v1, rho_new_1, r_new_1, s_new_1)
    val addr2 = KEY_PAIRS.get(choice.to2)
    val coin2 = mint_coin(addr2, v2, rho_new_2, r_new_2, s_new_2)

    val tx: PourTx = {
      sn_old_1: sn1,
      sn_old_2: sn2,
      cm_old_1: choice.c1.cm,
      cm_old_2: choice.c2.cm,
      cm_new_1: coin1.cm,
      cm_new_2: coin2.cm,
      v_pub: choice.vpub,
    }

    val witness: PourWitness = {
      c_old_1: choice.c1,
      c_old_2: choice.c2,
      ask_old_1: ask,
      ask_old_2: ask,
      c_new_1: coin1,
      c_new_2: coin2,
      phi: phi,
    }

    val is_valid = all {
      verify_pour_public(tx, ledger.commitments, ledger.serial_numbers),
      verify_pour_snark_fixed(tx, witness),
      my_wallet.contains(choice.c1),
      my_wallet.contains(choice.c2),
      choice.c1 != choice.c2,
    }

    all {
      is_valid,

      ledger' = {
        ...ledger,
        serial_numbers: ledger.serial_numbers.union(Set(sn1, sn2)),
        commitments: ledger.commitments.union(Set(coin1.cm, coin2.cm)),
        public_balance: ledger.public_balance.setBy(user, bal => bal + choice.vpub),
      },
      users' = {
        ...users,
        wallets: users.wallets
          .setBy(user, w => w.exclude(Set(choice.c1, choice.c2)))
          .setBy(choice.to1, w => w.union(Set(coin1)))
          .setBy(choice.to2, w => w.union(Set(coin2))),
        nonce_counters: users.nonce_counters.setBy(user, n => n + 2),
      },
    }
  }

  /// Honest nondeterministic step — VULNERABLE variant.
  action step = {
    nondet user = NODES.oneOf()
    any {
      nondet value = 1.to(INITIAL_BALANCE).oneOf()
      mint(user, value),

      nondet c1 = users.wallets.get(user).oneOf()
      nondet c2 = users.wallets.get(user).exclude(Set(c1)).oneOf()
      nondet to1 = NODES.oneOf()
      nondet to2 = NODES.oneOf()
      val total = c1.value + c2.value
      nondet v1 = 0.to(total).oneOf()
      nondet vpub = 0.to(total - v1).oneOf()
      pour(user, { c1: c1, c2: c2, to1: to1, to2: to2, v1: v1, vpub: vpub }),
    }
  }

  /// Honest nondeterministic step — FIXED variant.
  action step_fixed = {
    nondet user = NODES.oneOf()
    any {
      nondet value = 1.to(INITIAL_BALANCE).oneOf()
      mint(user, value),

      nondet c1 = users.wallets.get(user).oneOf()
      nondet c2 = users.wallets.get(user).exclude(Set(c1)).oneOf()
      nondet to1 = NODES.oneOf()
      nondet to2 = NODES.oneOf()
      val total = c1.value + c2.value
      nondet v1 = 0.to(total).oneOf()
      nondet vpub = 0.to(total - v1).oneOf()
      pour_fixed(user, { c1: c1, c2: c2, to1: to1, to2: to2, v1: v1, vpub: vpub }),
    }
  }

  // ===========================================================================
  // 8. BYZANTINE ACTIONS
  // ===========================================================================

  /// Faerie Gold attack — VULNERABLE variant.
  action faerie_gold_pour(
    user: Node,
    victim: Node,
    c1: Coin,
    c2: Coin,
    v1: CoinValue,
    vpub: CoinValue,
  ): bool = {
    val ask = SECRET_KEYS.get(user)
    val nc = users.nonce_counters.get(user)
    val my_wallet = users.wallets.get(user)
    val total = c1.value + c2.value
    val v2 = total - v1 - vpub

    val sn1 = compute_sn(ask, c1)
    val sn2 = compute_sn(ask, c2)

    // ATTACK: reuse the SAME rho for both output coins → same serial number
    val attack_rho = derive_rho_vulnerable(ask, nc, 0)
    val base = pair(ask, nc)
    val r = pair(base, 1)
    val s = pair(base, 2)

    val victim_addr = KEY_PAIRS.get(victim)
    val coin1 = mint_coin(victim_addr, v1, attack_rho, r, s)
    val coin2 = mint_coin(victim_addr, v2, attack_rho, r, s)

    val tx: PourTx = {
      sn_old_1: sn1,
      sn_old_2: sn2,
      cm_old_1: c1.cm,
      cm_old_2: c2.cm,
      cm_new_1: coin1.cm,
      cm_new_2: coin2.cm,
      v_pub: vpub,
    }

    val witness: PourWitness = {
      c_old_1: c1,
      c_old_2: c2,
      ask_old_1: ask,
      ask_old_2: ask,
      c_new_1: coin1,
      c_new_2: coin2,
      phi: 0,
    }

    val is_valid = all {
      verify_pour_public(tx, ledger.commitments, ledger.serial_numbers),
      verify_pour_snark(tx, witness),
      my_wallet.contains(c1),
      my_wallet.contains(c2),
      c1 != c2,
      v1 != v2,
      user != victim,
    }

    all {
      is_valid,

      ledger' = {
        ...ledger,
        serial_numbers: ledger.serial_numbers.union(Set(sn1, sn2)),
        commitments: ledger.commitments.union(Set(coin1.cm, coin2.cm)),
        public_balance: ledger.public_balance.setBy(user, bal => bal + vpub),
      },
      users' = {
        ...users,
        wallets: users.wallets
          .setBy(user, w => w.exclude(Set(c1, c2)))
          .setBy(victim, w => w.union(Set(coin1, coin2))),
        nonce_counters: users.nonce_counters.setBy(user, n => n + 1),
      },
    }
  }

  /// Faerie Gold attack — FIXED variant.
  /// Same attack but validated by verify_pour_snark_fixed, which requires
  /// coin_i.rho == derive_rho_fixed(sn1, sn2, phi, i). Since both coins share
  /// the same rho but derive_rho_fixed(..., 0) != derive_rho_fixed(..., 1)
  /// (last element of the list differs), this action is ALWAYS DISABLED.
  action faerie_gold_pour_fixed(
    user: Node,
    victim: Node,
    c1: Coin,
    c2: Coin,
    v1: CoinValue,
    vpub: CoinValue,
  ): bool = {
    val ask = SECRET_KEYS.get(user)
    val nc = users.nonce_counters.get(user)
    val my_wallet = users.wallets.get(user)
    val total = c1.value + c2.value
    val v2 = total - v1 - vpub

    val sn1 = compute_sn(ask, c1)
    val sn2 = compute_sn(ask, c2)

    // ATTACK: same duplicate rho as the vulnerable version
    val attack_rho = derive_rho_vulnerable(ask, nc, 0)
    val base = pair(ask, nc)
    val r = pair(base, 1)
    val s = pair(base, 2)

    val victim_addr = KEY_PAIRS.get(victim)
    val coin1 = mint_coin(victim_addr, v1, attack_rho, r, s)
    val coin2 = mint_coin(victim_addr, v2, attack_rho, r, s)

    val tx: PourTx = {
      sn_old_1: sn1,
      sn_old_2: sn2,
      cm_old_1: c1.cm,
      cm_old_2: c2.cm,
      cm_new_1: coin1.cm,
      cm_new_2: coin2.cm,
      v_pub: vpub,
    }

    val witness: PourWitness = {
      c_old_1: c1,
      c_old_2: c2,
      ask_old_1: ask,
      ask_old_2: ask,
      c_new_1: coin1,
      c_new_2: coin2,
      phi: 0,
    }

    val is_valid = all {
      verify_pour_public(tx, ledger.commitments, ledger.serial_numbers),
      verify_pour_snark_fixed(tx, witness),
      my_wallet.contains(c1),
      my_wallet.contains(c2),
      c1 != c2,
      v1 != v2,
      user != victim,
    }

    all {
      is_valid,

      ledger' = {
        ...ledger,
        serial_numbers: ledger.serial_numbers.union(Set(sn1, sn2)),
        commitments: ledger.commitments.union(Set(coin1.cm, coin2.cm)),
        public_balance: ledger.public_balance.setBy(user, bal => bal + vpub),
      },
      users' = {
        ...users,
        wallets: users.wallets
          .setBy(user, w => w.exclude(Set(c1, c2)))
          .setBy(victim, w => w.union(Set(coin1, coin2))),
        nonce_counters: users.nonce_counters.setBy(user, n => n + 1),
      },
    }
  }

  /// Faerie gold step — VULNERABLE variant.
  action faerie_gold_step = {
    nondet user = NODES.oneOf()
    any {
      step,

      nondet victim = NODES.exclude(Set(user)).oneOf()
      nondet c1 = users.wallets.get(user).oneOf()
      nondet c2 = users.wallets.get(user).exclude(Set(c1)).oneOf()
      val total = c1.value + c2.value
      nondet v1 = 0.to(total).oneOf()
      nondet vpub = 0.to(total - v1).oneOf()
      faerie_gold_pour(user, victim, c1, c2, v1, vpub),
    }
  }

  /// Faerie gold step — FIXED variant.
  action faerie_gold_step_fixed = {
    nondet user = NODES.oneOf()
    any {
      step_fixed,

      nondet victim = NODES.exclude(Set(user)).oneOf()
      nondet c1 = users.wallets.get(user).oneOf()
      nondet c2 = users.wallets.get(user).exclude(Set(c1)).oneOf()
      val total = c1.value + c2.value
      nondet v1 = 0.to(total).oneOf()
      nondet vpub = 0.to(total - v1).oneOf()
      faerie_gold_pour_fixed(user, victim, c1, c2, v1, vpub),
    }
  }

  // ===========================================================================
  // 9. INVARIANT HELPERS
  // ===========================================================================

  val total_public: int = {
    NODES.fold(0, (acc, u) => acc + ledger.public_balance.get(u))
  }

  val total_private: int = {
    NODES.fold(0, (acc, u) =>
      acc + users.wallets.get(u).fold(0, (a, c) => a + c.value)
    )
  }

  pure def eligible_coins(
    ask: AddrSk,
    wallet: Set[Coin],
    commitments: Set[Sym],
    serial_numbers: Set[Sym]
  ): Set[Coin] = {
    wallet.filter(c =>
      commitments.contains(c.cm) and
      not(serial_numbers.contains(compute_sn(ask, c)))
    )
  }

  // ===========================================================================
  // 10. INVARIANTS
  // ===========================================================================

  /// Invariant 1: No user has negative public balance.
  val no_negative_balances = NODES.forall(u =>
    ledger.public_balance.get(u) >= 0
  )

  /// Invariant 2: Exact balance conservation.
  val balance_conservation = {
    total_public + total_private == TOTAL_INITIAL
  }

  /// Invariant 3: Completeness (Definition III.1): all eligible coins have distinct serial numbers.
  /// Eligible means: cm on ledger, sn not on spent list.
  def user_completeness(u: Node): bool = {
    val ask = SECRET_KEYS.get(u)
    val elig = eligible_coins(
      ask,
      users.wallets.get(u),
      ledger.commitments,
      ledger.serial_numbers,
    )
    elig.forall(c1 =>
      elig.forall(c2 =>
        (c1 != c2) implies (compute_sn(ask, c1) != compute_sn(ask, c2))
      )
    )
  }

  /// All users satisfy per-user completeness.
  /// Cross-user sn collisions are impossible by PRF injectivity (distinct ask values).
  val completeness = NODES.forall(u => user_completeness(u))

  // ===========================================================================
  // 11. TESTS
  // ===========================================================================

  /// Full cycle test: Alice mints 2 coins, pours to Bob and Charlie.
  run fullCycleTest = {
    val alice_addr = KEY_PAIRS.get("alice")
    val alice_ask = SECRET_KEYS.get("alice")

    // Pre-compute coins (matching mint action's randomness generation)
    // Mint coin1: nc=0
    val base0 = pair(alice_ask, 0)
    val coin1 = mint_coin(alice_addr, 3, derive_rho_vulnerable(alice_ask, 0, 0), pair(base0, 1), pair(base0, 2))
    // Mint coin2: nc=1
    val base1 = pair(alice_ask, 1)
    val coin2 = mint_coin(alice_addr, 4, derive_rho_vulnerable(alice_ask, 1, 0), pair(base1, 1), pair(base1, 2))

    // Pour output coins (nc=2 after 2 mints)
    val pour_base1 = pair(alice_ask, 2)
    val pour_base2 = pair(alice_ask, 3)
    val bob_coin = mint_coin(KEY_PAIRS.get("bob"), 5, derive_rho_vulnerable(alice_ask, 2, 0), pair(pour_base1, 1), pair(pour_base1, 2))
    val charlie_coin = mint_coin(KEY_PAIRS.get("charlie"), 2, derive_rho_vulnerable(alice_ask, 2, 1), pair(pour_base2, 1), pair(pour_base2, 2))

    init
      .then(all {
        mint("alice", 3),
        assert(balance_conservation),
      })
      .then(all {
        mint("alice", 4),
        assert(balance_conservation),
      })
      .then(all {
        pour("alice", { c1: coin1, c2: coin2, to1: "bob", to2: "charlie", v1: 5, vpub: 0 }),
        assert(balance_conservation),
      })
      .then(all {
        assert(users.wallets.get("alice").size() == 0),
        assert(users.wallets.get("bob").size() == 1),
        assert(users.wallets.get("bob").forall(c => c.value == 5)),
        assert(users.wallets.get("charlie").size() == 1),
        assert(users.wallets.get("charlie").forall(c => c.value == 2)),
        assert(ledger.public_balance.get("alice") == 3),
        assert(ledger.serial_numbers.contains(compute_sn(alice_ask, coin1))),
        assert(ledger.serial_numbers.contains(compute_sn(alice_ask, coin2))),
        assert(balance_conservation),
        assert(no_negative_balances),
        ledger' = ledger,
        users' = users,
      })
  }

  /// Completeness test: verify pour is enabled when 2 eligible coins exist.
  run completenessTest = {
    val alice_addr = KEY_PAIRS.get("alice")
    val alice_ask = SECRET_KEYS.get("alice")
    val base0 = pair(alice_ask, 0)
    val base1 = pair(alice_ask, 1)
    val coin1 = mint_coin(alice_addr, 3, derive_rho_vulnerable(alice_ask, 0, 0), pair(base0, 1), pair(base0, 2))
    val coin2 = mint_coin(alice_addr, 4, derive_rho_vulnerable(alice_ask, 1, 0), pair(base1, 1), pair(base1, 2))

    init
      .then(mint("alice", 3))
      .then(mint("alice", 4))
      .then(all {
        assert(eligible_coins(
          alice_ask,
          users.wallets.get("alice"),
          ledger.commitments,
          ledger.serial_numbers,
        ).size() == 2),
        assert(completeness),
        assert(balance_conservation),
        assert(no_negative_balances),
        ledger' = ledger,
        users' = users,
      })
  }

  /// Faerie Gold test: core attack demonstration.
  run faerieGoldTest = {
    val alice_addr = KEY_PAIRS.get("alice")
    val alice_ask = SECRET_KEYS.get("alice")
    val bob_addr = KEY_PAIRS.get("bob")
    val bob_ask = SECRET_KEYS.get("bob")

    // Alice mints 2 coins (nc=0, nc=1)
    val base0 = pair(alice_ask, 0)
    val coin1 = mint_coin(alice_addr, 3, derive_rho_vulnerable(alice_ask, 0, 0), pair(base0, 1), pair(base0, 2))
    val base1 = pair(alice_ask, 1)
    val coin2 = mint_coin(alice_addr, 4, derive_rho_vulnerable(alice_ask, 1, 0), pair(base1, 1), pair(base1, 2))

    // Faerie gold output coins (Alice nc=2, reused rho for BOTH outputs)
    val attack_rho = derive_rho_vulnerable(alice_ask, 2, 0)
    val fg_base = pair(alice_ask, 2)
    val fg_r = pair(fg_base, 1)
    val fg_s = pair(fg_base, 2)
    val fg1 = mint_coin(bob_addr, 3, attack_rho, fg_r, fg_s)
    val fg2 = mint_coin(bob_addr, 4, attack_rho, fg_r, fg_s)

    init
      .then(mint("alice", 3))
      .then(mint("alice", 4))
      .then(faerie_gold_pour("alice", "bob", coin1, coin2, 3, 0))
      .then(all {
        assert(users.wallets.get("bob").size() == 2),
        assert(compute_sn(bob_ask, fg1) == compute_sn(bob_ask, fg2)),
        assert(fg1.cm != fg2.cm),

        // --- Completeness VIOLATED ---
        assert(not(completeness)),

        // --- Balance STILL HOLDS ---
        assert(balance_conservation),

        ledger' = ledger,
        users' = users,
      })
  }

  /// Faerie Gold spend cascade test.
  run faerieGoldSpendCascadeTest = {
    val alice_addr = KEY_PAIRS.get("alice")
    val alice_ask = SECRET_KEYS.get("alice")
    val bob_addr = KEY_PAIRS.get("bob")
    val bob_ask = SECRET_KEYS.get("bob")

    // Bob mints legit coin (nc=0)
    val base_bob0 = pair(bob_ask, 0)
    val legit_coin = mint_coin(bob_addr, 2, derive_rho_vulnerable(bob_ask, 0, 0), pair(base_bob0, 1), pair(base_bob0, 2))

    // Alice mints 2 coins (nc=0, nc=1)
    val base_a0 = pair(alice_ask, 0)
    val alice_coin1 = mint_coin(alice_addr, 3, derive_rho_vulnerable(alice_ask, 0, 0), pair(base_a0, 1), pair(base_a0, 2))
    val base_a1 = pair(alice_ask, 1)
    val alice_coin2 = mint_coin(alice_addr, 4, derive_rho_vulnerable(alice_ask, 1, 0), pair(base_a1, 1), pair(base_a1, 2))

    // Faerie gold output coins (Alice nc=2, reused rho)
    val attack_rho = derive_rho_vulnerable(alice_ask, 2, 0)
    val fg_base = pair(alice_ask, 2)
    val fg_r = pair(fg_base, 1)
    val fg_s = pair(fg_base, 2)
    val fg1 = mint_coin(bob_addr, 3, attack_rho, fg_r, fg_s)
    val fg2 = mint_coin(bob_addr, 4, attack_rho, fg_r, fg_s)

    // Pour output coins (Bob nc=1 after his 1 mint)
    val pour_base1 = pair(bob_ask, 1)
    val pour_base2 = pair(bob_ask, 2)
    val new_coin1 = mint_coin(bob_addr, 5, derive_rho_vulnerable(bob_ask, 1, 0), pair(pour_base1, 1), pair(pour_base1, 2))
    val new_coin2 = mint_coin(bob_addr, 0, derive_rho_vulnerable(bob_ask, 1, 1), pair(pour_base2, 1), pair(pour_base2, 2))

    init
      .then(mint("bob", 2))
      .then(mint("alice", 3))
      .then(mint("alice", 4))
      .then(faerie_gold_pour("alice", "bob", alice_coin1, alice_coin2, 3, 0))
      .then(pour("bob", { c1: legit_coin, c2: fg1, to1: "bob", to2: "bob", v1: 5, vpub: 0 }))
      .then(all {
        assert(users.wallets.get("bob").contains(fg2)),
        assert(ledger.serial_numbers.contains(compute_sn(bob_ask, fg2))),
        assert(completeness),  // zombie coin is ineligible, so completeness holds
        assert(not(eligible_coins(
          bob_ask,
          users.wallets.get("bob"),
          ledger.commitments,
          ledger.serial_numbers,
        ).contains(fg2))),
        ledger' = ledger,
        users' = users,
      })
  }
}
