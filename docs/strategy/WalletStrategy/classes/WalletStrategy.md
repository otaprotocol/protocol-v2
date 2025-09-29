[**@actioncodes/protocol-v2**](../../../README.md)

***

[@actioncodes/protocol-v2](../../../modules.md) / [strategy/WalletStrategy](../README.md) / WalletStrategy

# Class: WalletStrategy

Defined in: src/strategy/WalletStrategy.ts:11

## Constructors

### Constructor

> **new WalletStrategy**(): `WalletStrategy`

#### Returns

`WalletStrategy`

## Methods

### generateCode()

> `static` **generateCode**(`pubkey`, `config`, `providedSecret?`): [`CodeGenerationResult`](../../../types/interfaces/CodeGenerationResult.md)

Defined in: src/strategy/WalletStrategy.ts:12

#### Parameters

##### pubkey

`string`

##### config

[`CodeGenerationConfig`](../../../types/interfaces/CodeGenerationConfig.md)

##### providedSecret?

`string`

#### Returns

[`CodeGenerationResult`](../../../types/interfaces/CodeGenerationResult.md)

***

### validateCode()

> `static` **validateCode**(`actionCode`, `config`): `void`

Defined in: src/strategy/WalletStrategy.ts:48

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

##### config

[`CodeGenerationConfig`](../../../types/interfaces/CodeGenerationConfig.md)

#### Returns

`void`
