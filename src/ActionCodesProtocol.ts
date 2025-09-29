import type { ActionCode, CodeGenerationConfig } from "./types";
import type { ChainContext, ChainAdapter } from "./adapters/BaseChainAdapter";
import { WalletStrategy } from "./strategy/WalletStrategy";
import { serializeCanonical } from "./utils/canonical";
import { SolanaAdapter, type SolanaContext } from "./adapters/SolanaAdapter";

export class ActionCodesProtocol {
  private adapters: Record<string, ChainAdapter> = {};

  constructor(private readonly config: CodeGenerationConfig) {
    // Register default adapters
    this.adapters.solana = new SolanaAdapter() as ChainAdapter<SolanaContext>;
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

  generateCode(pubkey: string, providedSecret?: string): {
    actionCode: ActionCode;
    canonicalMessage: Uint8Array;
  } {
    return WalletStrategy.generateCode(pubkey, this.config, providedSecret);
  }

  async validateCode(
    actionCode: ActionCode,
    chain?: string,
    context?: Omit<ChainContext<unknown>, "message">
  ): Promise<void> {
    // This will throw if validation fails
    WalletStrategy.validateCode(actionCode, this.config);

    if (!chain) return;

    const adapter = this.getAdapter(chain);
    if (!adapter) return;

    const canonical = serializeCanonical({
      pubkey: actionCode.pubkey,
      windowStart: actionCode.timestamp,
    });

    const ok = adapter.verify({
      ...(context as unknown as ChainContext<unknown>),
      message: canonical,
      chain,
    } as unknown as ChainContext<unknown>);

    if (!ok) {
      throw new Error("Signature verification failed");
    }
  }
}
