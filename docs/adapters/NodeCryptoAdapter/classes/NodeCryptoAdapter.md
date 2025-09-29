[**@actioncodes/protocol-v2**](../../../README.md)

***

[@actioncodes/protocol-v2](../../../modules.md) / [adapters/NodeCryptoAdapter](../README.md) / NodeCryptoAdapter

# Class: NodeCryptoAdapter

Defined in: src/adapters/NodeCryptoAdapter.ts:20

## Extends

- [`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md)\<[`NodeCryptoContext`](../type-aliases/NodeCryptoContext.md)\>

## Constructors

### Constructor

> **new NodeCryptoAdapter**(): `NodeCryptoAdapter`

#### Returns

`NodeCryptoAdapter`

#### Inherited from

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`constructor`](../../BaseChainAdapter/classes/BaseChainAdapter.md#constructor)

## Methods

### getProtocolMeta()

> **getProtocolMeta**(`tx`): `null` \| `string`

Defined in: src/adapters/NodeCryptoAdapter.ts:57

Extract protocol metadata from a simulated transaction

#### Parameters

##### tx

###### instructions?

`object`[]

#### Returns

`null` \| `string`

***

### parseMeta()

> **parseMeta**(`tx`): `null` \| [`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

Defined in: src/adapters/NodeCryptoAdapter.ts:74

Get parsed ProtocolMeta object, or null if none or invalid

#### Parameters

##### tx

###### instructions?

`object`[]

#### Returns

`null` \| [`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

***

### verify()

> **verify**(`context`): `boolean`

Defined in: src/adapters/NodeCryptoAdapter.ts:22

Verify the signature over canonical message using Node.js crypto

#### Parameters

##### context

[`ChainContext`](../../BaseChainAdapter/type-aliases/ChainContext.md)\<[`NodeCryptoContext`](../type-aliases/NodeCryptoContext.md)\>

#### Returns

`boolean`

#### Overrides

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`verify`](../../BaseChainAdapter/classes/BaseChainAdapter.md#verify)

***

### verifyTransactionMatchesCode()

> **verifyTransactionMatchesCode**(`actionCode`, `tx`): `void`

Defined in: src/adapters/NodeCryptoAdapter.ts:84

Validate that a transaction's meta aligns with the bound `actionCode`.
Throws ProtocolError if validation fails.

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

##### tx

###### instructions?

`object`[]

#### Returns

`void`

***

### verifyTransactionSignedByIntentOwner()

> **verifyTransactionSignedByIntentOwner**(`tx`): `void`

Defined in: src/adapters/NodeCryptoAdapter.ts:125

Verify that the transaction is signed by the "intendedFor" pubkey
as declared in the protocol meta of the transaction.
Throws ProtocolError if validation fails.

#### Parameters

##### tx

###### instructions?

`object`[]

###### signatures?

`object`[]

#### Returns

`void`

***

### attachProtocolMeta()

> `static` **attachProtocolMeta**(`tx`, `meta`): `object`

Defined in: src/adapters/NodeCryptoAdapter.ts:159

Attach protocol meta to a simulated transaction.

#### Parameters

##### tx

###### instructions?

`object`[]

##### meta

[`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

#### Returns

`object`

##### instructions

> **instructions**: `object`[]

***

### createProtocolMetaInstruction()

> `static` **createProtocolMetaInstruction**(`meta`): `object`

Defined in: src/adapters/NodeCryptoAdapter.ts:46

Create a protocol meta instruction for NodeCrypto (simulated)

#### Parameters

##### meta

[`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

#### Returns

`object`

##### data

> **data**: `string`

##### type

> **type**: `string`

***

### generateKeyPair()

> `static` **generateKeyPair**(): `object`

Defined in: src/adapters/NodeCryptoAdapter.ts:185

Generate a key pair for testing

#### Returns

`object`

##### privateKey

> **privateKey**: `KeyObject`

##### publicKey

> **publicKey**: `KeyObject`

***

### signMessage()

> `static` **signMessage**(`message`, `privateKey`): `string`

Defined in: src/adapters/NodeCryptoAdapter.ts:173

Sign a message with a private key

#### Parameters

##### message

`Uint8Array`

##### privateKey

`KeyObject`

#### Returns

`string`
