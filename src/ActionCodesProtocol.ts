import type {
  ActionCode,
  CodeGenerationConfig,
  DelegationProof,
  DelegatedActionCode,
} from "./types";
import type {
  ChainAdapter,
  WalletContext,
  DelegatedContext,
} from "./adapters/BaseChainAdapter";
import { WalletStrategy } from "./strategy/WalletStrategy";
import { DelegationStrategy } from "./strategy/DelegationStrategy";
import { SolanaAdapter } from "./adapters/SolanaAdapter";
import { ProtocolError } from "./errors";

export class ActionCodesProtocol {
  private adapters: Record<string, ChainAdapter> = {};
  private _walletStrategy: WalletStrategy;
  private _delegationStrategy: DelegationStrategy;

  constructor(private readonly config: CodeGenerationConfig) {
    // Register default adapters
    this.adapters.solana = new SolanaAdapter() as unknown as ChainAdapter;

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
    signature: string
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
    signature?: string
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
      return this.walletStrategy.generateCode(param1 as Uint8Array, signature);
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
    context?: WalletContext<unknown>
  ): void;
  validateCode(
    strategy: "delegation",
    actionCode: DelegatedActionCode,
    context?: DelegatedContext<unknown>
  ): void;
  validateCode(
    strategy: "wallet" | "delegation",
    actionCode: ActionCode | DelegatedActionCode,
    param2?: WalletContext<unknown> | DelegatedContext<unknown>
  ): void {
    if (strategy === "wallet") {
      // This will throw if validation fails
      this.walletStrategy.validateCode(actionCode as ActionCode);

      if (!param2) return;

      const context = param2 as Omit<WalletContext<unknown>, "message">;
      const adapter = this.getAdapter(context.chain);
      if (!adapter) throw ProtocolError.invalidAdapter(context.chain);

      const ok = adapter.verifyWithWallet({
        ...(context as Record<string, unknown>),
        message: {
          pubkey: (actionCode as ActionCode).pubkey,
          windowStart: (actionCode as ActionCode).timestamp,
        },
      } as unknown as WalletContext<unknown>);

      if (!ok) {
        throw ProtocolError.invalidSignature(
          "Wallet signature verification failed"
        );
      }
    } else {
      const context = param2 as Omit<DelegatedContext<unknown>, "message">;

      // CRITICAL: First validate the delegated action code
      // This ensures the code was actually generated from this delegation proof
      this.delegationStrategy.validateDelegatedCode(
        actionCode as DelegatedActionCode,
        context.delegationProof
      );

      // Then verify the delegation proof signature
      const adapter = this.getAdapter(context.chain);
      if (!adapter) throw ProtocolError.invalidAdapter(context.chain);

      const ok = adapter.verifyWithDelegation({
        ...(context as Record<string, unknown>),
        message: {
          pubkey: (actionCode as ActionCode).pubkey,
          windowStart: (actionCode as ActionCode).timestamp,
        },
      } as unknown as DelegatedContext<unknown>);

      if (!ok) {
        throw ProtocolError.invalidSignature(
          "Delegation signature verification failed"
        );
      }
    }
  }
}
