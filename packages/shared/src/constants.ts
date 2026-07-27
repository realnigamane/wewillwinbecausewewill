/**
 * Chain constants.
 *
 * Every event topic0 in this file was computed with a local Keccak-256
 * implementation that was self-tested against the canonical hashes for
 * Transfer(address,address,uint256) and Approval(address,address,uint256)
 * before being trusted. See `scripts/verify-constants.ts` to re-derive them.
 */

// ---------------------------------------------------------------------------
// Block boundaries
// ---------------------------------------------------------------------------

/**
 * First Ethereum block of 2024 (2024-01-01T00:00:00Z), approximately.
 * HyperSync treats `toBlock` as EXCLUSIVE, so passing this value scans
 * everything strictly before 2024.
 *
 * This is an approximation good to a few blocks. If you need it exact, run
 * `pnpm indexer resolve-block 2024-01-01T00:00:00Z`, which binary-searches
 * block timestamps over RPC and prints the true boundary.
 */
export const PRE_2024_END_BLOCK = 18_908_895;

// ---------------------------------------------------------------------------
// Event signatures -> topic0
// ---------------------------------------------------------------------------

/**
 * Uniswap V2 style. Emitted by the V2 factory AND by every fork of it
 * (SushiSwap, ShibaSwap, PancakeSwap-on-ETH, and several hundred one-off
 * forks). We deliberately do NOT filter by factory address — scanning by
 * topic0 alone discovers every fork for free, including ones nobody has
 * catalogued. The emitting contract address in each log IS the factory,
 * so factories are an output of the scan rather than an input.
 *
 * event PairCreated(address indexed token0, address indexed token1, address pair, uint256 allPairsLength)
 *   topic1 = token0, topic2 = token1
 *   data   = [ pair (word 0), allPairsLength (word 1) ]
 */
export const TOPIC_PAIR_CREATED =
  '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9';

/**
 * Uniswap V3 style.
 *
 * event PoolCreated(address indexed token0, address indexed token1, uint24 indexed fee, int24 tickSpacing, address pool)
 *   topic1 = token0, topic2 = token1, topic3 = fee
 *   data   = [ tickSpacing (word 0), pool (word 1) ]   <-- pool is the SECOND word
 */
export const TOPIC_POOL_CREATED =
  '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118';

/**
 * Uniswap V1 style — the ORIGINAL DEX (Nov 2018 – 2020). Pre-dates V2 entirely,
 * so it's the only way to see 2018–2020 liquidity. Every V1 exchange is an
 * ETH/token pool AND its own ERC-20 LP token, so it fits the same locked-LP
 * analysis as V2 once discovered.
 *
 * event NewExchange(address indexed token, address indexed exchange)
 *   topic1 = token, topic2 = exchange (the pool + the LP token)
 */
export const TOPIC_NEW_EXCHANGE =
  '0x9d42cb017eb05bd8944ab536a8b35bc68085931dd5f4356489801453923953f9';

/** Balancer V2 registers pools against a singleton Vault. Different shape; see notes in README. */
export const TOPIC_POOL_REGISTERED =
  '0x3c13bc30b8e878c53fd2a36b679409c073afd75950be43d8858768e956fbc20e';

/** ERC-20 Transfer — used to reconstruct LP token flows when we need holder history. */
export const TOPIC_TRANSFER =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

export type PoolKind = 'v1' | 'v2' | 'v3';

export const TOPIC_TO_KIND: Record<string, PoolKind> = {
  [TOPIC_PAIR_CREATED]: 'v2',
  [TOPIC_POOL_CREATED]: 'v3',
  [TOPIC_NEW_EXCHANGE]: 'v1',
};

// ---------------------------------------------------------------------------
// Infrastructure contracts
// ---------------------------------------------------------------------------

/** Multicall3 — same address on every EVM chain via deterministic deployment. */
export const MULTICALL3 = '0xcA11bde05977b3631167028862bE2a173976CA11';

/** Chainlink ETH/USD price feed. Lets us price pools with zero external API keys. */
export const CHAINLINK_ETH_USD = '0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419';

/** WETH — used as the ETH-side proxy for Uniswap V1 exchanges (which hold raw ETH). */
export const WETH_ADDRESS = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';

/** Uniswap V3 NonfungiblePositionManager — holds V3 liquidity as NFTs. */
export const UNIV3_POSITION_MANAGER = '0xC36442b4a4522E871399CD717aBDD847Ab11FE88';

// ---------------------------------------------------------------------------
// Quote assets — the denominators we can price a pool in
// ---------------------------------------------------------------------------

export interface QuoteAsset {
  address: string;
  symbol: string;
  decimals: number;
  /** 'eth' -> value via Chainlink ETH/USD. 'usd' -> already dollar-denominated. */
  peg: 'eth' | 'usd';
}

export const QUOTE_ASSETS: Record<string, QuoteAsset> = {
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': {
    address: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
    symbol: 'WETH',
    decimals: 18,
    peg: 'eth',
  },
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': {
    address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
    symbol: 'USDC',
    decimals: 6,
    peg: 'usd',
  },
  '0xdac17f958d2ee523a2206206994597c13d831ec7': {
    address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
    symbol: 'USDT',
    decimals: 6,
    peg: 'usd',
  },
  '0x6b175474e89094c44da98b954eedeac495271d0f': {
    address: '0x6b175474e89094c44da98b954eedeac495271d0f',
    symbol: 'DAI',
    decimals: 18,
    peg: 'usd',
  },
  '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599': {
    address: '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599',
    symbol: 'WBTC',
    decimals: 8,
    peg: 'usd', // priced via its own feed; see pricing.ts
  },
  '0x853d955acef822db058eb8505911ed77f175b99e': {
    address: '0x853d955acef822db058eb8505911ed77f175b99e',
    symbol: 'FRAX',
    decimals: 18,
    peg: 'usd',
  },
};

export const isQuoteAsset = (addr: string) => addr.toLowerCase() in QUOTE_ASSETS;

// ---------------------------------------------------------------------------
// Burn addresses — LP sent here is permanently, provably unrecoverable
// ---------------------------------------------------------------------------

export const BURN_ADDRESSES = [
  '0x0000000000000000000000000000000000000000',
  '0x000000000000000000000000000000000000dead',
  '0x0000000000000000000000000000000000000001',
  '0xdead000000000000000042069420694206942069',
] as const;

// ---------------------------------------------------------------------------
// LP locker registry
// ---------------------------------------------------------------------------

export interface Locker {
  address: string;
  name: string;
  /**
   * false  => address recalled from memory, NOT confirmed against a primary source.
   *
   * These are treated as UNTRUSTED until `pnpm indexer verify-lockers` confirms
   * (a) the address holds deployed bytecode, and (b) it actually holds LP token
   * balances for known pairs. Unverified entries are excluded from the strict
   * `locked_usd` figure and surface only as `suspected` in the UI, so a wrong
   * address here can never silently inflate results.
   */
  verified: boolean;
  /** Whether unlock timestamps can be read on-chain (implementation varies per locker). */
  queryableUnlock: boolean;
}

export const LOCKERS: Locker[] = [
  { address: '0x663a5c229c09b049e36dcc11a9b0d4a8eb9db214', name: 'UNCX / Unicrypt V2', verified: false, queryableUnlock: true },
  { address: '0x17e00383a843a9922bca3b280c0ade9f8ba48449', name: 'Unicrypt (legacy)', verified: false, queryableUnlock: true },
  { address: '0xe2fe530c047f2d85298b07d9333c05737f1435fb', name: 'Team Finance', verified: false, queryableUnlock: true },
  { address: '0x71b5759d73262fbb223956913ecf4ecc51057641', name: 'PinkLock v2', verified: false, queryableUnlock: true },
];

/**
 * The registry above is a convenience, not the source of truth.
 *
 * The scanner's primary lock signal is structural and needs no registry at all:
 * for each pair we resolve the top LP holders, then classify each holder as
 * BURN (dead address), CONTRACT (has bytecode => cannot be an EOA rug-pull, so
 * the LP is at minimum not casually withdrawable), or EOA. This catches lockers
 * nobody has ever catalogued, which matters a lot for 2020-2022 era launches.
 */
export const LOCK_CLASSIFICATION = ['burned', 'locker_known', 'locker_unknown_contract', 'eoa'] as const;
export type LockClassification = (typeof LOCK_CLASSIFICATION)[number];
