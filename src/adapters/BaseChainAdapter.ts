import type { CanonicalMessageParts, DelegationCertificate } from "../types";

// Chain context and adapter interface live here to avoid coupling core types to chain specifics.
export interface BaseWalletStrategyContext {
  chain: string;
  // Canonical message bytes used for signature verification
  canonicalMessageParts: CanonicalMessageParts;
}

export interface BaseDelegationContext {
  chain: string;
  pubkey: string;
  signature: string;
  certificate: DelegationCertificate;
}

export type ChainWalletStrategyContext<T> = BaseWalletStrategyContext & T;
export type ChainDelegationStrategyContext<T> = BaseDelegationContext & T;
export interface ChainAdapter<TCtx = unknown, DCtx = unknown> {
  verifyWithWallet(context: ChainWalletStrategyContext<TCtx>): boolean;
  verifyWithDelegation(context: ChainDelegationStrategyContext<DCtx>): boolean;
}

export abstract class BaseChainAdapter<TCtx, DCtx> implements ChainAdapter<TCtx, DCtx> {
  abstract verifyWithWallet(context: ChainWalletStrategyContext<TCtx>): boolean;
  abstract verifyWithDelegation(context: ChainDelegationStrategyContext<DCtx>): boolean;
}
