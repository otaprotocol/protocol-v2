import type {
  ActionCode,
  CodeGenerationConfig,
  DelegationProof,
  DelegatedActionCode,
} from "./types";
import type {
  ChainAdapter,
  ChainWalletStrategyContext,
  ChainDelegationStrategyContext,
} from "./adapters/BaseChainAdapter";
import { WalletStrategy } from "./strategy/WalletStrategy";
import { DelegationStrategy } from "./strategy/DelegationStrategy";
import { SolanaAdapter, type SolanaContext } from "./adapters/SolanaAdapter";
import { ProtocolError } from "./errors";

export class ActionCodesProtocol {
  private adapters: Record<string, ChainAdapter> = {};
  private _walletStrategy: WalletStrategy;
  private _delegationStrategy: DelegationStrategy;

  constructor(private readonly config: CodeGenerationConfig) {
    // Register default adapters
    this.adapters.solana = new SolanaAdapter() as ChainAdapter<SolanaContext>;

    // Initialize strategies
    this._walletStrategy = new WalletStrategy(config);
    this._delegationStrategy = new DelegationStrategy(config);
  }

  public getConfig(): CodeGenerationConfig {
    return this.config;
  }

  /** Register a chain adapter */
  registerAdapter(chain: string, adapter: ChainAdapter): void {
    this.adapters[chain] = adapter;
  }

  /** Get a registered adapter */
  getAdapter(chain: string): ChainAdapter | undefined {
    return this.adapters[chain];
  }

  /** Typed access to specific adapters */
  get adapter() {
    return {
      solana: this.adapters.solana as unknown as SolanaAdapter,
    };
  }

  /** Access to strategies */
  get walletStrategy() {
    return this._walletStrategy;
  }

  get delegationStrategy() {
    return this._delegationStrategy;
  }

  // Generate code
  generateCode(
    strategy: "wallet",
    canonicalMessage: Uint8Array,
    signature: string,
    providedSecret?: string
  ): {
    actionCode: ActionCode;
    canonicalMessage: Uint8Array;
  };
  generateCode(
    strategy: "delegation",
    delegationProof: DelegationProof,
    delegatedSignature: string
  ): {
    actionCode: DelegatedActionCode;
  };
  generateCode(
    strategy: "wallet" | "delegation",
    param1: Uint8Array | DelegationProof,
    signature?: string,
    providedSecret?: string
  ): {
    actionCode: ActionCode | DelegatedActionCode;
    canonicalMessage?: Uint8Array;
  } {
    if (strategy === "wallet") {
      // Here param1 must be Uint8Array (canonical message)
      if (!signature) {
        throw ProtocolError.invalidSignature(
          "Missing signature over canonical message"
        );
      }
      return this.walletStrategy.generateCode(
        param1 as Uint8Array,
        signature,
        providedSecret
      );
    } else {
      // Here param1 must be DelegationProof
      if (!signature) {
        throw ProtocolError.invalidSignature("Missing delegated signature");
      }
      return this.delegationStrategy.generateDelegatedCode(
        param1 as DelegationProof,
        signature
      );
    }
  }

  // Overloaded validateCode methods with strategy parameter
  validateCode(
    strategy: "wallet",
    actionCode: ActionCode,
    context?: Omit<ChainWalletStrategyContext<unknown>, "canonicalMessageParts">
  ): void;
  validateCode(
    strategy: "delegation",
    actionCode: DelegatedActionCode,
    context?: Omit<
      ChainDelegationStrategyContext<unknown>,
      "canonicalMessageParts"
    >
  ): void;
  validateCode(
    strategy: "wallet" | "delegation",
    actionCode: ActionCode | DelegatedActionCode,
    param2?:
      | Omit<ChainWalletStrategyContext<unknown>, "canonicalMessageParts">
      | Omit<ChainDelegationStrategyContext<unknown>, "canonicalMessageParts">
  ): void {
    if (strategy === "wallet") {
      // This will throw if validation fails
      this.walletStrategy.validateCode(actionCode as ActionCode);

      if (!param2) return;

      const context = param2 as Omit<
        ChainWalletStrategyContext<unknown>,
        "canonicalMessageParts"
      >;
      const adapter = this.getAdapter(context.chain);
      if (!adapter) throw ProtocolError.invalidAdapter(context.chain);

      const ok = adapter.verifyWithWallet({
        ...context,
        canonicalMessageParts: {
          pubkey: actionCode.pubkey,
          windowStart: actionCode.timestamp,
        },
      } as unknown as ChainWalletStrategyContext<unknown>);

      if (!ok) {
        throw new Error("Signature verification failed");
      }
    } else {
      const context = param2 as Omit<
        ChainDelegationStrategyContext<unknown>,
        "canonicalMessageParts"
      >;

      // CRITICAL: First validate the delegated action code
      // This ensures the code was actually generated from this delegation proof
      this.delegationStrategy.validateDelegatedCode(
        actionCode as DelegatedActionCode,
        context.delegationProof
      );

      // Then verify the delegation proof signature
      const adapter = this.getAdapter(context.chain);
      if (!adapter) throw ProtocolError.invalidAdapter(context.chain);

      const ok = adapter.verifyWithDelegation(
        context as unknown as ChainDelegationStrategyContext<unknown>
      );

      if (!ok) {
        throw new Error("Signature verification failed");
      }
    }
  }
}
