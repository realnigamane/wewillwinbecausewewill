import type { PoolKind, LockClassification } from '@liqarch/shared';

export interface DiscoveredPool {
  address: string;
  kind: PoolKind;
  factory: string;
  token0: string;
  token1: string;
  feeTier: number | null;
  createdBlock: number;
  createdTs: number | null;
  createdTx: string | null;
}

export interface ValuedPool extends DiscoveredPool {
  quoteSide: 0 | 1;
  reserve0: bigint;
  reserve1: bigint;
  lpTotalSupply: bigint;
  totalLiquidityUsd: number;
}

export interface HolderRecord {
  holder: string;
  balance: bigint;
  fraction: number;
  classification: LockClassification;
  lockerName: string | null;
  unlockAt: Date | null;
}

export interface PoolWithLocks extends ValuedPool {
  lpBurned: bigint;
  lpLockedKnown: bigint;
  lpLockedUnknownContract: bigint;
  lockedFraction: number;
  lockedLiquidityUsd: number;
  burnedLiquidityUsd: number;
  earliestUnlockAt: Date | null;
  holders: HolderRecord[];
  passesThreshold: boolean;
}
