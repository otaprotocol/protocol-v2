import type { CanonicalMessageParts, CanonicalRevokeMessageParts, DelegationCertificate } from "../types";

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

export interface BaseWalletStrategyRevokeContext {
  chain: string;
  // Canonical revoke message bytes used for signature verification
  canonicalRevokeMessageParts: CanonicalRevokeMessageParts;
}

export type ChainWalletStrategyContext<T> = BaseWalletStrategyContext & T;
export type ChainWalletStrategyRevokeContext<T> = BaseWalletStrategyRevokeContext & T;
export type ChainDelegationStrategyContext<T> = BaseDelegationContext & T;
export interface ChainAdapter<TCtx = unknown, DCtx = unknown, RCtx = unknown> {
  verifyWithWallet(context: ChainWalletStrategyContext<TCtx>): boolean;
  verifyWithDelegation(context: ChainDelegationStrategyContext<DCtx>): boolean;
  verifyRevokeWithWallet(context: ChainWalletStrategyRevokeContext<RCtx>): boolean;
}

export abstract class BaseChainAdapter<TCtx, DCtx, RCtx> implements ChainAdapter<TCtx, DCtx, RCtx> {
  abstract verifyWithWallet(context: ChainWalletStrategyContext<TCtx>): boolean;
  abstract verifyWithDelegation(context: ChainDelegationStrategyContext<DCtx>): boolean;
  abstract verifyRevokeWithWallet(context: ChainWalletStrategyRevokeContext<RCtx>): boolean;
}
