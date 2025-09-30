import type {
  ActionCode,
  CodeGenerationConfig,
  DelegationCertificate,
  DelegatedActionCode,
} from "./types";
import type {
  ChainAdapter,
  ChainWalletStrategyContext,
} from "./adapters/BaseChainAdapter";
import { WalletStrategy } from "./strategy/WalletStrategy";
import { DelegationStrategy } from "./strategy/DelegationStrategy";
import { SolanaAdapter, type SolanaContext } from "./adapters/SolanaAdapter";

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

  // Delegation Strategy Methods
  createDelegationCertificateTemplate(
    userPublicKey: string,
    durationMs: number = 3600000,
    chain: string = "solana"
  ): Omit<DelegationCertificate, "signature"> {
    return DelegationStrategy.createDelegationCertificateTemplate(
      userPublicKey,
      durationMs,
      chain
    );
  }

  // Generate code
  generateCode(
    strategy: "wallet",
    pubkey: string,
    providedSecret?: string
  ): {
    actionCode: ActionCode;
    canonicalMessage: Uint8Array;
  };
  generateCode(
    strategy: "delegation",
    certificate: DelegationCertificate
  ): {
    actionCode: DelegatedActionCode;
  };

  generateCode(
    strategy: "wallet" | "delegation",
    param1: string | DelegationCertificate,
    providedSecret?: string
  ): {
    actionCode: ActionCode | DelegatedActionCode;
    canonicalMessage?: Uint8Array;
  } {
    if (strategy === "wallet") {
      // Here param1 must be string
      return this.walletStrategy.generateCode(param1 as string, providedSecret);
    } else {
      // Here param1 must be DelegationCertificate
      return this.delegationStrategy.generateDelegatedCode(
        param1 as DelegationCertificate
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
    certificate: DelegationCertificate
  ): void;
  validateCode(
    strategy: "wallet" | "delegation",
    actionCode: ActionCode | DelegatedActionCode,
    param2?:
      | DelegationCertificate
      | Omit<ChainWalletStrategyContext<unknown>, "canonicalMessageParts">
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
      if (!adapter) return;

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
      const certificate = param2 as DelegationCertificate;
      const adapter = this.getAdapter(certificate.chain);
      if (!adapter) return;

      const ok = adapter.verifyWithDelegation({
        chain: certificate.chain,
        pubkey: certificate.delegator,
        signature: certificate.signature,
        certificate: certificate,
      });

      if (!ok) {
        throw new Error("Signature verification failed");
      }
    }
  }
}
