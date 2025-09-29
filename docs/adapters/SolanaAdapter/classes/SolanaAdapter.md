[**@actioncodes/protocol-v2**](../../../README.md)

***

[@actioncodes/protocol-v2](../../../modules.md) / [adapters/SolanaAdapter](../README.md) / SolanaAdapter

# Class: SolanaAdapter

Defined in: src/adapters/SolanaAdapter.ts:30

## Extends

- [`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md)\<[`SolanaContext`](../type-aliases/SolanaContext.md)\>

## Constructors

### Constructor

> **new SolanaAdapter**(): `SolanaAdapter`

#### Returns

`SolanaAdapter`

#### Inherited from

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`constructor`](../../BaseChainAdapter/classes/BaseChainAdapter.md#constructor)

## Methods

### getProtocolMeta()

> **getProtocolMeta**(`tx`): `null` \| `string`

Defined in: src/adapters/SolanaAdapter.ts:81

Extract protocol metadata string (memo) from a transaction, or null

#### Parameters

##### tx

[`SolanaTransaction`](../type-aliases/SolanaTransaction.md)

#### Returns

`null` \| `string`

***

### parseMeta()

> **parseMeta**(`tx`): `null` \| [`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

Defined in: src/adapters/SolanaAdapter.ts:97

Get parsed ProtocolMeta object, or null if none or invalid

#### Parameters

##### tx

[`SolanaTransaction`](../type-aliases/SolanaTransaction.md)

#### Returns

`null` \| [`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

***

### verify()

> **verify**(`context`): `boolean`

Defined in: src/adapters/SolanaAdapter.ts:40

Verify the signature over canonical message (protocol-level)

#### Parameters

##### context

[`ChainContext`](../../BaseChainAdapter/type-aliases/ChainContext.md)\<[`SolanaContext`](../type-aliases/SolanaContext.md)\>

#### Returns

`boolean`

#### Overrides

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`verify`](../../BaseChainAdapter/classes/BaseChainAdapter.md#verify)

***

### verifyTransactionMatchesCode()

> **verifyTransactionMatchesCode**(`actionCode`, `tx`): `void`

Defined in: src/adapters/SolanaAdapter.ts:143

Validate that a transaction's memo meta aligns with the bound `actionCode`.
Throws ProtocolError if validation fails.

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

##### tx

[`SolanaTransaction`](../type-aliases/SolanaTransaction.md)

#### Returns

`void`

***

### verifyTransactionSignedByIntentOwner()

> **verifyTransactionSignedByIntentOwner**(`tx`): `void`

Defined in: src/adapters/SolanaAdapter.ts:184

Verify that the transaction is signed by the "intendedFor" pubkey
as declared in the protocol meta of the transaction.
Throws ProtocolError if validation fails.

#### Parameters

##### tx

[`SolanaTransaction`](../type-aliases/SolanaTransaction.md)

#### Returns

`void`

***

### attachProtocolMeta()

> `static` **attachProtocolMeta**\<`T`\>(`tx`, `meta`): `T`

Defined in: src/adapters/SolanaAdapter.ts:257

Attach protocol meta into a legacy or versioned transaction.

⚠️ Note: this mutates the given transaction.

#### Type Parameters

##### T

`T` *extends* [`SolanaTransaction`](../type-aliases/SolanaTransaction.md)

#### Parameters

##### tx

`T`

##### meta

[`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

#### Returns

`T`

***

### createProtocolMetaIx()

> `static` **createProtocolMetaIx**(`meta`): `TransactionInstruction`

Defined in: src/adapters/SolanaAdapter.ts:73

Create a Solana memo instruction carrying protocol meta (for SDK/clients)

#### Parameters

##### meta

[`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

#### Returns

`TransactionInstruction`
