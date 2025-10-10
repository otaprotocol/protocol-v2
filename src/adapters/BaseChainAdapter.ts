import type {
  CanonicalMessageParts,
  CanonicalRevokeMessageParts,
  DelegationProof,
} from "../types";

export interface BaseContext {
  chain: string;
}

export type WalletContext<TChain = unknown> = BaseContext &
  TChain & {
    message: CanonicalMessageParts;
    walletSignature: string;
  };

export type DelegatedContext<TChain = unknown> = BaseContext &
  TChain & {
    message: CanonicalMessageParts;
    delegatedSignature: string;
    delegationProof: DelegationProof;
  };

export type WalletRevokeContext<TChain = unknown> = BaseContext &
  TChain & {
    message: CanonicalRevokeMessageParts;
    walletSignature: string;
  };

export type DelegatedRevokeContext<TChain = unknown> = BaseContext &
  TChain & {
    message: CanonicalRevokeMessageParts;
    delegatedSignature: string;
    delegationProof: DelegationProof;
  };

export interface ChainAdapter<
  TW = unknown,
  DW = unknown,
  RW = unknown,
  RD = unknown
> {
  verifyWithWallet(context: WalletContext<TW>): boolean;
  verifyWithDelegation(context: DelegatedContext<DW>): boolean;
  verifyRevokeWithWallet(context: WalletRevokeContext<RW>): boolean;
  verifyRevokeWithDelegation(context: DelegatedRevokeContext<RD>): boolean;
}

export abstract class BaseChainAdapter<TW, DW, RW, RD>
  implements ChainAdapter<TW, DW, RW, RD>
{
  abstract verifyWithWallet(context: WalletContext<TW>): boolean;
  abstract verifyWithDelegation(context: DelegatedContext<DW>): boolean;
  abstract verifyRevokeWithWallet(context: WalletRevokeContext<RW>): boolean;
  abstract verifyRevokeWithDelegation(
    context: DelegatedRevokeContext<RD>
  ): boolean;
}
