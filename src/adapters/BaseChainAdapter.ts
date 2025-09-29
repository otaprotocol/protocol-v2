import type { CanonicalMessageParts } from "../types";

// Chain context and adapter interface live here to avoid coupling core types to chain specifics.
export interface BaseContext {
  // Canonical message bytes used for signature verification
  canonicalMessageParts: CanonicalMessageParts;
}
export type ChainContext<T> = BaseContext & { chain: string } & T;

export interface ChainAdapter<TCtx = unknown> {
  verify(context: ChainContext<TCtx>): boolean;
}

export abstract class BaseChainAdapter<TCtx> implements ChainAdapter<TCtx> {
  abstract verify(context: ChainContext<TCtx>): boolean;
}
