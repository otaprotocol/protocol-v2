[**@actioncodes/protocol-v2**](../../../README.md)

***

[@actioncodes/protocol-v2](../../../modules.md) / [adapters/BaseChainAdapter](../README.md) / BaseChainAdapter

# Abstract Class: BaseChainAdapter\<TCtx\>

Defined in: src/adapters/BaseChainAdapter.ts:14

## Extended by

- [`NodeCryptoAdapter`](../../NodeCryptoAdapter/classes/NodeCryptoAdapter.md)
- [`SolanaAdapter`](../../SolanaAdapter/classes/SolanaAdapter.md)

## Type Parameters

### TCtx

`TCtx`

## Implements

- [`ChainAdapter`](../interfaces/ChainAdapter.md)\<`TCtx`\>

## Constructors

### Constructor

> **new BaseChainAdapter**\<`TCtx`\>(): `BaseChainAdapter`\<`TCtx`\>

#### Returns

`BaseChainAdapter`\<`TCtx`\>

## Methods

### verify()

> `abstract` **verify**(`context`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:15

#### Parameters

##### context

[`ChainContext`](../type-aliases/ChainContext.md)\<`TCtx`\>

#### Returns

`boolean`

#### Implementation of

[`ChainAdapter`](../interfaces/ChainAdapter.md).[`verify`](../interfaces/ChainAdapter.md#verify)
