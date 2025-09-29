[**@actioncodes/protocol-v2**](../../README.md)

***

[@actioncodes/protocol-v2](../../modules.md) / [ActionCodesProtocol](../README.md) / ActionCodesProtocol

# Class: ActionCodesProtocol

Defined in: src/ActionCodesProtocol.ts:7

## Constructors

### Constructor

> **new ActionCodesProtocol**(`config`): `ActionCodesProtocol`

Defined in: src/ActionCodesProtocol.ts:10

#### Parameters

##### config

[`CodeGenerationConfig`](../../types/interfaces/CodeGenerationConfig.md)

#### Returns

`ActionCodesProtocol`

## Accessors

### adapter

#### Get Signature

> **get** **adapter**(): `object`

Defined in: src/ActionCodesProtocol.ts:26

Typed access to specific adapters

##### Returns

`object`

###### solana

> **solana**: [`SolanaAdapter`](../../adapters/SolanaAdapter/classes/SolanaAdapter.md)

## Methods

### generateCode()

> **generateCode**(`pubkey`, `providedSecret?`): `object`

Defined in: src/ActionCodesProtocol.ts:32

#### Parameters

##### pubkey

`string`

##### providedSecret?

`string`

#### Returns

`object`

##### actionCode

> **actionCode**: [`ActionCode`](../../types/interfaces/ActionCode.md)

##### canonicalMessage

> **canonicalMessage**: `Uint8Array`

***

### getAdapter()

> **getAdapter**(`chain`): `undefined` \| [`ChainAdapter`](../../adapters/BaseChainAdapter/interfaces/ChainAdapter.md)\<`unknown`\>

Defined in: src/ActionCodesProtocol.ts:21

Get a registered adapter

#### Parameters

##### chain

`string`

#### Returns

`undefined` \| [`ChainAdapter`](../../adapters/BaseChainAdapter/interfaces/ChainAdapter.md)\<`unknown`\>

***

### registerAdapter()

> **registerAdapter**(`chain`, `adapter`): `void`

Defined in: src/ActionCodesProtocol.ts:16

Register a chain adapter

#### Parameters

##### chain

`string`

##### adapter

[`ChainAdapter`](../../adapters/BaseChainAdapter/interfaces/ChainAdapter.md)

#### Returns

`void`

***

### validateCode()

> **validateCode**(`actionCode`, `chain?`, `context?`): `Promise`\<`void`\>

Defined in: src/ActionCodesProtocol.ts:39

#### Parameters

##### actionCode

[`ActionCode`](../../types/interfaces/ActionCode.md)

##### chain?

`string`

##### context?

`Omit`\<[`ChainContext`](../../adapters/BaseChainAdapter/type-aliases/ChainContext.md)\<`unknown`\>, `"message"`\>

#### Returns

`Promise`\<`void`\>
