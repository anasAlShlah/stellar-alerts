import { describe, it, expect, beforeEach } from 'vitest';
import crypto from 'crypto';
import {
  PayloadMaskingEngine,
  payloadMaskingEngine,
  parsePath,
  type MaskingRule,
  type MaskingConfig,
} from './payload-masker';
import { generateWebhookSignature, verifyWebhookSignatureSync } from '../../utils/webhook-signer';

describe('PayloadMaskingEngine (#990)', () => {
  const sampleStellarAlert = {
    event: 'payment.received',
    timestamp: '2026-11-22T12:00:00.000Z',
    data: {
      paymentId: 'pay_99887766',
      txHash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      amount: '1500.50',
      asset: 'USDC',
      assetIssuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
      from: 'GDQ2WY7C4XZ4GZKV4YHKD7K4R7W2F23WEXJ62N7S7G3N57SZS37B',
      to: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
      memo: 'Confidential client invoice #4421',
      operations: [
        {
          id: 'op_1',
          sourceAccount: 'GDQ2WY7C4XZ4GZKV4YHKD7K4R7W2F23WEXJ62N7S7G3N57SZS37B',
          amount: '1500.50',
          memo: 'Private note',
        },
        {
          id: 'op_2',
          sourceAccount: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
          amount: '50.00',
          memo: 'Fee split',
        },
      ],
      metadata: {
        client: {
          name: 'Acme Corp',
          email: 'finance@acme.com',
          ipAddress: '192.168.1.100',
        },
      },
    },
  };

  beforeEach(() => {
    payloadMaskingEngine.clearRules();
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 1. Path Parsing Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe('Path Parsing & Targeting', () => {
    it('parses simple dot-notation paths', () => {
      const res = parsePath('data.memo');
      expect(res.segments).toEqual(['data', 'memo']);
      expect(res.isDeepScan).toBe(false);
    });

    it('parses JSONPath paths with leading $. and $', () => {
      expect(parsePath('$.data.from').segments).toEqual(['data', 'from']);
      expect(parsePath('$data.to').segments).toEqual(['data', 'to']);
      expect(parsePath('$.memo').segments).toEqual(['memo']);
    });

    it('parses array bracket notations and wildcards', () => {
      expect(parsePath('data.operations[*].sourceAccount').segments).toEqual([
        'data',
        'operations',
        '*',
        'sourceAccount',
      ]);
      expect(parsePath('data.operations[0].id').segments).toEqual(['data', 'operations', 0, 'id']);
      expect(parsePath('data["metadata"][\'client\'].email').segments).toEqual([
        'data',
        'metadata',
        'client',
        'email',
      ]);
    });

    it('identifies deep recursive scan paths', () => {
      const res = parsePath('data..memo');
      expect(res.isDeepScan).toBe(true);
      expect(res.deepScanKey).toBe('memo');
    });

    it('handles empty or invalid paths gracefully', () => {
      expect(parsePath('').segments).toEqual([]);
      expect(parsePath('   ').segments).toEqual([]);
      expect(parsePath(null as any).segments).toEqual([]);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 2. REDACT Policy Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe('REDACT Policy', () => {
    it('replaces target field with [REDACTED] by default', () => {
      const rules: MaskingRule[] = [{ path: 'data.memo', policy: 'REDACT' }];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.memo).toBe('[REDACTED]');
      expect(result.data.amount).toBe('1500.50'); // other fields intact
      expect(sampleStellarAlert.data.memo).toBe('Confidential client invoice #4421'); // original untouched
    });

    it('supports custom redactValue placeholder', () => {
      const rules: MaskingRule[] = [
        { path: 'data.memo', policy: 'REDACT', redactValue: '[CONFIDENTIAL_MEMO]' },
      ];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.memo).toBe('[CONFIDENTIAL_MEMO]');
    });

    it('redacts top-level field', () => {
      const payload = { memo: 'Secret note', from: 'GD123' };
      const rules: MaskingRule[] = [{ path: 'memo', policy: 'REDACT' }];
      const result = PayloadMaskingEngine.mask(payload, rules);

      expect(result.memo).toBe('[REDACTED]');
      expect(result.from).toBe('GD123');
    });

    it('redacts primitive numbers, booleans, and nested objects', () => {
      const payload = { data: { count: 42, active: true, inner: { secret: 'abc' } } };
      const rules: MaskingRule[] = [
        { path: 'data.count', policy: 'REDACT' },
        { path: 'data.active', policy: 'REDACT' },
        { path: 'data.inner', policy: 'REDACT' },
      ];
      const result = PayloadMaskingEngine.mask(payload, rules);

      expect(result.data.count).toBe('[REDACTED]');
      expect(result.data.active).toBe('[REDACTED]');
      expect(result.data.inner).toBe('[REDACTED]');
    });

    it('redacts fields across all array elements using wildcard [*]', () => {
      const rules: MaskingRule[] = [{ path: 'data.operations[*].memo', policy: 'REDACT' }];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.operations[0].memo).toBe('[REDACTED]');
      expect(result.data.operations[1].memo).toBe('[REDACTED]');
      expect(result.data.operations[0].id).toBe('op_1');
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 3. SHA256_SALTED Policy Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe('SHA256_SALTED Policy', () => {
    const customSalt = 'analytics-partner-corp-secret-salt-2026';

    it('produces a valid 64-character hex SHA-256 hash', () => {
      const rules: MaskingRule[] = [
        { path: 'data.from', policy: 'SHA256_SALTED', salt: customSalt },
      ];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.from).toMatch(/^[a-f0-9]{64}$/);
      expect(result.data.from).not.toBe(sampleStellarAlert.data.from);
    });

    it('guarantees deterministic output for the same input and salt', () => {
      const rules: MaskingRule[] = [
        { path: 'data.from', policy: 'SHA256_SALTED', salt: customSalt },
      ];

      const result1 = PayloadMaskingEngine.mask(sampleStellarAlert, rules);
      const result2 = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      // Repeat transactions from the same address must correlate deterministically
      expect(result1.data.from).toBe(result2.data.from);
    });

    it('produces completely different hashes when different salts are used', () => {
      const rules1: MaskingRule[] = [
        { path: 'data.from', policy: 'SHA256_SALTED', salt: 'salt-tenant-A' },
      ];
      const rules2: MaskingRule[] = [
        { path: 'data.from', policy: 'SHA256_SALTED', salt: 'salt-tenant-B' },
      ];

      const result1 = PayloadMaskingEngine.mask(sampleStellarAlert, rules1);
      const result2 = PayloadMaskingEngine.mask(sampleStellarAlert, rules2);

      expect(result1.data.from).not.toBe(result2.data.from);
    });

    it('falls back to engine default salt when rule does not specify a salt', () => {
      const engine = new PayloadMaskingEngine({
        rules: [{ path: 'data.from', policy: 'SHA256_SALTED' }],
        defaultSalt: 'configured-engine-salt-xyz',
      });

      const result = engine.mask(sampleStellarAlert);
      const expectedHash = crypto
        .createHash('sha256')
        .update(`configured-engine-salt-xyz:${sampleStellarAlert.data.from}`)
        .digest('hex');

      expect(result.data.from).toBe(expectedHash);
    });

    it('hashes nested array items deterministically', () => {
      const rules: MaskingRule[] = [
        { path: 'data.operations[*].sourceAccount', policy: 'SHA256_SALTED', salt: customSalt },
      ];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.operations[0].sourceAccount).toMatch(/^[a-f0-9]{64}$/);
      expect(result.data.operations[1].sourceAccount).toMatch(/^[a-f0-9]{64}$/);
      expect(result.data.operations[0].sourceAccount).not.toBe(
        result.data.operations[1].sourceAccount
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 4. TRUNCATE Policy Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe('TRUNCATE Policy', () => {
    it('truncates Stellar address preserving prefix and suffix: GD...7B', () => {
      // sampleStellarAlert.data.from = 'GDQ2WY7C4XZ4GZKV4YHKD7K4R7W2F23WEXJ62N7S7G3N57SZS37B'
      const rules: MaskingRule[] = [{ path: 'data.from', policy: 'TRUNCATE' }];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      // Prefix (2) = 'GD', Suffix (2) = '7B', Separator = '...'
      expect(result.data.from).toBe('GD...7B');
    });

    it('supports custom prefixLength and suffixLength (e.g. 4 prefix, 4 suffix)', () => {
      const rules: MaskingRule[] = [
        {
          path: 'data.from',
          policy: 'TRUNCATE',
          truncateOptions: { prefixLength: 4, suffixLength: 4, separator: '...' },
        },
      ];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.from).toBe('GDQ2...S37B');
    });

    it('supports custom separator string', () => {
      const rules: MaskingRule[] = [
        {
          path: 'data.from',
          policy: 'TRUNCATE',
          truncateOptions: { prefixLength: 3, suffixLength: 3, separator: '---' },
        },
      ];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.from).toBe('GDQ---37B');
    });

    it('handles short strings safely without throwing or distorting', () => {
      expect(PayloadMaskingEngine.truncate('ABCD')).toBe('ABCD');
      expect(PayloadMaskingEngine.truncate('ABCDE')).toBe('AB...DE');
      expect(PayloadMaskingEngine.truncate('AB')).toBe('AB');
      expect(PayloadMaskingEngine.truncate('')).toBe('');
      expect(PayloadMaskingEngine.truncate(null as any)).toBe('');
    });

    it('truncates txHash preserving prefix and suffix', () => {
      const rules: MaskingRule[] = [
        {
          path: 'data.txHash',
          policy: 'TRUNCATE',
          truncateOptions: { prefixLength: 6, suffixLength: 6, separator: '...' },
        },
      ];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.txHash).toBe('0x1234...abcdef');
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 5. OMIT Policy Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe('OMIT Policy', () => {
    it('completely removes top-level property from payload', () => {
      const payload = { memo: 'Top secret', amount: '100.00', from: 'GAAA' };
      const rules: MaskingRule[] = [{ path: 'memo', policy: 'OMIT' }];
      const result = PayloadMaskingEngine.mask(payload, rules);

      expect(result).not.toHaveProperty('memo');
      expect(result.amount).toBe('100.00');
      expect(result.from).toBe('GAAA');
    });

    it('completely removes nested property from payload', () => {
      const rules: MaskingRule[] = [{ path: 'data.memo', policy: 'OMIT' }];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data).not.toHaveProperty('memo');
      expect(result.data.amount).toBe('1500.50');
      expect(result.data.from).toBe(sampleStellarAlert.data.from);
    });

    it('removes target property across all objects in an array', () => {
      const rules: MaskingRule[] = [{ path: 'data.operations[*].memo', policy: 'OMIT' }];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result.data.operations[0]).not.toHaveProperty('memo');
      expect(result.data.operations[1]).not.toHaveProperty('memo');
      expect(result.data.operations[0].id).toBe('op_1');
      expect(result.data.operations[1].id).toBe('op_2');
    });

    it('removes specific array index element', () => {
      const payload = { items: ['apple', 'banana', 'cherry'] };
      const rules: MaskingRule[] = [{ path: 'items[1]', policy: 'OMIT' }];
      const result = PayloadMaskingEngine.mask(payload, rules);

      expect(result.items).toEqual(['apple', 'cherry']);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 6. Comprehensive Multi-Policy Policy Engine Integration
  // ──────────────────────────────────────────────────────────────────────────
  describe('Multi-Policy Composition', () => {
    it('applies all 4 policies simultaneously to a complex nested alert payload', () => {
      const engine = new PayloadMaskingEngine();
      engine.addRules([
        { path: 'data.memo', policy: 'REDACT' },
        { path: 'data.from', policy: 'SHA256_SALTED', salt: 'test-salt' },
        { path: 'data.to', policy: 'TRUNCATE' },
        { path: 'data.amount', policy: 'OMIT' },
        { path: 'data.metadata.client.ipAddress', policy: 'REDACT', redactValue: 'xxx.xxx.xxx.xxx' },
      ]);

      const masked = engine.mask(sampleStellarAlert);

      // 1. REDACT check
      expect(masked.data.memo).toBe('[REDACTED]');
      expect(masked.data.metadata.client.ipAddress).toBe('xxx.xxx.xxx.xxx');

      // 2. SHA256_SALTED check
      expect(masked.data.from).toMatch(/^[a-f0-9]{64}$/);
      expect(masked.data.from).not.toBe(sampleStellarAlert.data.from);

      // 3. TRUNCATE check
      expect(masked.data.to).toBe('GB...A5');

      // 4. OMIT check
      expect(masked.data).not.toHaveProperty('amount');

      // Untouched fields
      expect(masked.event).toBe('payment.received');
      expect(masked.data.asset).toBe('USDC');
      expect(masked.data.metadata.client.name).toBe('Acme Corp');
    });

    it('supports deep scan wildcard across all occurrences in nested payload', () => {
      const payload = {
        memo: 'root memo',
        data: {
          memo: 'level 1 memo',
          nested: {
            memo: 'deep memo',
            other: 'keep this',
          },
        },
      };

      const rules: MaskingRule[] = [{ path: '..memo', policy: 'REDACT' }];
      const result = PayloadMaskingEngine.mask(payload, rules);

      expect(result.memo).toBe('[REDACTED]');
      expect(result.data.memo).toBe('[REDACTED]');
      expect(result.data.nested.memo).toBe('[REDACTED]');
      expect(result.data.nested.other).toBe('keep this');
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 7. HMAC Webhook Signature Verification Prior to Signing
  // ──────────────────────────────────────────────────────────────────────────
  describe('Cryptographic Signature HMAC Integration', () => {
    it('executes masking prior to HMAC generation and signs the exact masked body', () => {
      const secret = 'whsec_enterprise_audit_pipeline_secret_4488';
      const rules: MaskingRule[] = [
        { path: 'data.memo', policy: 'REDACT' },
        { path: 'data.from', policy: 'SHA256_SALTED', salt: 'partner-salt' },
        { path: 'data.to', policy: 'TRUNCATE' },
      ];

      // 1. Mask payload
      const maskedPayload = PayloadMaskingEngine.mask(sampleStellarAlert, rules);
      const payloadString = JSON.stringify(maskedPayload);

      // 2. Generate HMAC signature on the masked payload
      const timestamp = Date.now();
      const nonce = 'masking-test-nonce-001';
      const signatureResult = generateWebhookSignature(payloadString, secret, timestamp, nonce);

      // 3. Verify that the HMAC signature is mathematically valid for the masked payload using codebase verifier
      const isValidMasked = verifyWebhookSignatureSync(payloadString, signatureResult.headerValue, secret);
      expect(isValidMasked).toBe(true);

      // 4. Verify that unmasked payload fails signature verification (confirming strict integrity)
      const unmaskedString = JSON.stringify(sampleStellarAlert);
      const isValidUnmasked = verifyWebhookSignatureSync(unmaskedString, signatureResult.headerValue, secret);
      expect(isValidUnmasked).toBe(false);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 8. Webhook Entity Rule Extraction Tests
  // ──────────────────────────────────────────────────────────────────────────
  describe('Webhook Entity Rule Extraction', () => {
    it('extracts rules from webhook.maskingRules property', () => {
      const webhook = {
        id: 'wh_1',
        url: 'https://analytics.example.com/webhook',
        maskingRules: [{ path: 'data.memo', policy: 'REDACT' }],
      };

      const extracted = PayloadMaskingEngine.extractRules(webhook);
      expect(extracted).toHaveLength(1);
      expect(extracted![0].path).toBe('data.memo');
    });

    it('extracts rules from JSON payloadTemplate', () => {
      const webhook = {
        id: 'wh_2',
        url: 'https://analytics.example.com/webhook',
        payloadTemplate: JSON.stringify({
          maskingRules: [
            { path: 'data.from', policy: 'SHA256_SALTED' },
            { path: 'data.to', policy: 'TRUNCATE' },
          ],
        }),
      };

      const extracted = PayloadMaskingEngine.extractRules(webhook);
      expect(extracted).toHaveLength(2);
      expect(extracted![0].policy).toBe('SHA256_SALTED');
      expect(extracted![1].policy).toBe('TRUNCATE');
    });

    it('returns null when webhook has no masking configuration', () => {
      const webhook = {
        id: 'wh_3',
        url: 'https://example.com/webhook',
        payloadTemplate: '{{data.amount}} received',
      };

      expect(PayloadMaskingEngine.extractRules(webhook)).toBeNull();
      expect(PayloadMaskingEngine.extractRules(null)).toBeNull();
    });

    it('maskWebhookPayload automatically applies rules when present', () => {
      const webhook = {
        payloadTemplate: JSON.stringify({
          maskingRules: [{ path: 'data.memo', policy: 'REDACT' }],
        }),
      };

      const masked = PayloadMaskingEngine.maskWebhookPayload(sampleStellarAlert, webhook);
      expect(masked.data.memo).toBe('[REDACTED]');
    });

    it('maskWebhookPayload returns original payload when no rules are present', () => {
      const webhook = { payloadTemplate: null };
      const masked = PayloadMaskingEngine.maskWebhookPayload(sampleStellarAlert, webhook);
      expect(masked).toBe(sampleStellarAlert);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 9. Edge Cases & Resilience
  // ──────────────────────────────────────────────────────────────────────────
  describe('Resilience & Edge Cases', () => {
    it('handles non-existent paths gracefully without mutating or throwing', () => {
      const rules: MaskingRule[] = [
        { path: 'data.nonExistentKey.nestedProperty', policy: 'REDACT' },
        { path: 'totallyMissing', policy: 'OMIT' },
      ];
      const result = PayloadMaskingEngine.mask(sampleStellarAlert, rules);

      expect(result).toEqual(sampleStellarAlert);
    });

    it('handles null and undefined input payloads safely', () => {
      expect(PayloadMaskingEngine.mask(null, [{ path: 'x', policy: 'REDACT' }])).toBeNull();
      expect(PayloadMaskingEngine.mask(undefined, [{ path: 'x', policy: 'REDACT' }])).toBeUndefined();
    });

    it('masks raw JSON string with maskJson', () => {
      const json = JSON.stringify({ memo: 'secret', amount: 50 });
      const maskedJson = payloadMaskingEngine.maskJson(json, [
        { path: 'memo', policy: 'REDACT' },
      ]);
      const parsed = JSON.parse(maskedJson);

      expect(parsed.memo).toBe('[REDACTED]');
      expect(parsed.amount).toBe(50);
    });

    it('guarantees source payload immutability', () => {
      const source = { data: { memo: 'initial memo', from: 'GAAA' } };
      const frozenSource = JSON.parse(JSON.stringify(source));

      PayloadMaskingEngine.mask(source, [
        { path: 'data.memo', policy: 'REDACT' },
        { path: 'data.from', policy: 'OMIT' },
      ]);

      expect(source).toEqual(frozenSource);
    });

    it('covers engine lifecycle methods: addRules, getRules, hasRules, setSalt, clearRules', () => {
      const engine = new PayloadMaskingEngine();
      expect(engine.hasRules()).toBe(false);
      expect(engine.getRules()).toEqual([]);

      engine.addRules([
        { path: 'memo', policy: 'REDACT' },
        { path: 'from', policy: 'TRUNCATE' },
      ]);
      expect(engine.hasRules()).toBe(true);
      expect(engine.getRules()).toHaveLength(2);

      engine.setSalt('custom-salt-123');
      engine.clearRules();
      expect(engine.hasRules()).toBe(false);
      expect(engine.getRules()).toHaveLength(0);
    });

    it('initializes from MaskingConfig with deterministicSecret and custom defaults', () => {
      const config: MaskingConfig = {
        rules: [{ path: 'memo', policy: 'REDACT' }],
        deterministicSecret: 'secret-key-xyz',
        truncateDefaults: { prefixLength: 3, suffixLength: 3, separator: '---' },
        redactDefault: '[SECRET]',
      };
      const engine = new PayloadMaskingEngine(config);
      const res = engine.mask({ memo: 'hello' });
      expect(res.memo).toBe('[SECRET]');
    });

    it('supports override rules with config object containing deterministicSecret', () => {
      const engine = new PayloadMaskingEngine();
      const res = engine.mask(
        { from: 'GD123456789' },
        {
          rules: [{ path: 'from', policy: 'SHA256_SALTED' }],
          deterministicSecret: 'override-secret-key',
        }
      );
      expect(res.from).toMatch(/^[a-f0-9]{64}$/);
    });

    it('handles wildcard * targeting all properties of an object', () => {
      const payload = { a: 'foo', b: 'bar', c: 'baz' };
      const res = PayloadMaskingEngine.mask(payload, [{ path: '*', policy: 'REDACT' }]);
      expect(res.a).toBe('[REDACTED]');
      expect(res.b).toBe('[REDACTED]');
      expect(res.c).toBe('[REDACTED]');

      const resOmit = PayloadMaskingEngine.mask(payload, [{ path: '*', policy: 'OMIT' }]);
      expect(Object.keys(resOmit)).toHaveLength(0);
    });

    it('handles wildcard * targeting all items of a root array', () => {
      const payload = ['secret1', 'secret2', 'secret3'];
      const res = PayloadMaskingEngine.mask(payload, [{ path: '*', policy: 'REDACT' }]);
      expect(res).toEqual(['[REDACTED]', '[REDACTED]', '[REDACTED]']);

      const resOmit = PayloadMaskingEngine.mask(payload, [{ path: '*', policy: 'OMIT' }]);
      expect(resOmit).toEqual([]);
    });

    it('handles extractRules with various webhook payloadTemplate formats', () => {
      // payloadTemplate with maskRules key
      expect(
        PayloadMaskingEngine.extractRules({
          payloadTemplate: JSON.stringify({ maskRules: [{ path: 'x', policy: 'OMIT' }] }),
        })
      ).toHaveLength(1);

      // payloadTemplate with rules key
      expect(
        PayloadMaskingEngine.extractRules({
          payloadTemplate: JSON.stringify({ rules: [{ path: 'y', policy: 'REDACT' }] }),
        })
      ).toHaveLength(1);

      // payloadTemplate as object with maskingRules
      expect(
        PayloadMaskingEngine.extractRules({
          payloadTemplate: { maskingRules: [{ path: 'z', policy: 'TRUNCATE' }] },
        })
      ).toHaveLength(1);

      // payloadTemplate as object with rules
      expect(
        PayloadMaskingEngine.extractRules({
          payloadTemplate: { rules: [{ path: 'z2', policy: 'OMIT' }] },
        })
      ).toHaveLength(1);

      // webhook with direct rules property
      expect(
        PayloadMaskingEngine.extractRules({
          rules: [{ path: 'w', policy: 'REDACT' }],
        })
      ).toHaveLength(1);

      // array passed directly
      expect(PayloadMaskingEngine.extractRules([{ path: 'v', policy: 'OMIT' }])).toHaveLength(1);
    });

    it('tests static redact method directly', () => {
      expect(PayloadMaskingEngine.redact()).toBe('[REDACTED]');
      expect(PayloadMaskingEngine.redact('anything', 'MASKED')).toBe('MASKED');
    });

    it('handles sha256Salted with objects, numbers, and null values', () => {
      expect(PayloadMaskingEngine.sha256Salted({ nested: 'val' })).toMatch(/^[a-f0-9]{64}$/);
      expect(PayloadMaskingEngine.sha256Salted(12345)).toMatch(/^[a-f0-9]{64}$/);
      expect(PayloadMaskingEngine.sha256Salted(null)).toMatch(/^[a-f0-9]{64}$/);
    });

    it('handles truncate on single-char and two-char strings', () => {
      expect(PayloadMaskingEngine.truncate('A')).toBe('A');
      expect(PayloadMaskingEngine.truncate('AB')).toBe('AB');
    });

    it('returns original string when maskJson receives non-JSON', () => {
      expect(payloadMaskingEngine.maskJson('not a valid json')).toBe('not a valid json');
      expect(payloadMaskingEngine.maskJson('')).toBe('');
      expect(payloadMaskingEngine.maskJson(null as any)).toBeNull();
    });

    it('leaves value unchanged when unknown policy is specified', () => {
      const payload = { memo: 'test' };
      const res = PayloadMaskingEngine.mask(payload, [
        { path: 'memo', policy: 'UNKNOWN_POLICY_XYZ' as any },
      ]);
      expect(res.memo).toBe('test');
    });
  });
});
