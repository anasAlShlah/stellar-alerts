import crypto from 'crypto';

/**
 * Supported field-level masking policies.
 */
export type MaskingPolicy = 'REDACT' | 'SHA256_SALTED' | 'TRUNCATE' | 'OMIT';

export interface TruncateOptions {
  /** Number of characters to preserve at the start (default: 2) */
  prefixLength?: number;
  /** Number of characters to preserve at the end (default: 2) */
  suffixLength?: number;
  /** Separator placed between prefix and suffix (default: '...') */
  separator?: string;
}

export interface MaskingRule {
  /**
   * Dot-notation or JSONPath targeting path.
   * Examples: 'memo', 'data.memo', '$.data.from', 'operations[*].from', 'items[0].id'
   */
  path: string;
  /** Masking policy to apply */
  policy: MaskingPolicy | string;
  /** Optional custom salt for SHA256_SALTED hashing */
  salt?: string;
  /** Options for TRUNCATE policy */
  truncateOptions?: TruncateOptions;
  /** Custom replacement value for REDACT policy (default: '[REDACTED]') */
  redactValue?: string;
}

export interface MaskingConfig {
  /** Array of declarative masking rules */
  rules: MaskingRule[];
  /** Default salt for deterministic salted SHA-256 hashing */
  defaultSalt?: string;
  /** Deterministic secret key */
  deterministicSecret?: string;
  /** Default truncate options */
  truncateDefaults?: TruncateOptions;
  /** Default redaction placeholder */
  redactDefault?: string;
}

export type PathSegment = string | number;

/** Default deterministic salt used when none is provided in rule or environment */
const DEFAULT_SYSTEM_SALT =
  process.env.WEBHOOK_MASKING_SALT ||
  process.env.WEBHOOK_SECRET_KEY ||
  'stellar-alerts-deterministic-masking-salt-v1';

const DEFAULT_REDACT_PLACEHOLDER = '[REDACTED]';

const DEFAULT_TRUNCATE_OPTIONS: Required<TruncateOptions> = {
  prefixLength: 2,
  suffixLength: 2,
  separator: '...',
};

/**
 * Deep clones any JSON-compatible structure or JavaScript object safely.
 */
function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  if (obj instanceof Date) {
    return new Date(obj.getTime()) as unknown as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => deepClone(item)) as unknown as T;
  }
  const copy: Record<string, any> = {};
  for (const [key, value] of Object.entries(obj)) {
    copy[key] = deepClone(value);
  }
  return copy as T;
}

/**
 * Parses a dot-notation or JSONPath string into an array of path segments.
 *
 * Supports:
 * - Simple dot notation: 'data.memo', 'memo', 'from'
 * - JSONPath prefixes: '$.data.from', '$.memo'
 * - Array brackets: 'operations[0].from', 'data["items"][*].to'
 * - Wildcards: 'operations[*].from', 'data.*.address', '*'
 * - Deep recursive wildcards: '..memo', '$.data..amount'
 */
export function parsePath(path: string): { segments: PathSegment[]; isDeepScan: boolean; deepScanKey?: string } {
  if (!path || typeof path !== 'string') {
    return { segments: [], isDeepScan: false };
  }

  let clean = path.trim();

  // Strip leading $. or $
  if (clean.startsWith('$.')) {
    clean = clean.slice(2);
  } else if (clean.startsWith('$')) {
    clean = clean.slice(1);
    if (clean.startsWith('.')) {
      clean = clean.slice(1);
    }
  }

  // Check for deep recursive wildcard scan (e.g. '..memo' or 'data..amount')
  if (clean.includes('..')) {
    const parts = clean.split('..');
    const targetKey = parts[parts.length - 1].replace(/[\[\]'"]/g, '').trim();
    return {
      segments: [],
      isDeepScan: true,
      deepScanKey: targetKey,
    };
  }

  // Convert array and bracket notations: [0] -> .0, ['prop'] -> .prop, [*] -> .*
  clean = clean.replace(/\[\s*(['"]?)(.*?)\1\s*\]/g, '.$2');

  const parts = clean.split('.').filter((p) => p.length > 0);

  const segments: PathSegment[] = parts.map((part) => {
    if (part === '*') return '*';
    if (/^\d+$/.test(part)) return parseInt(part, 10);
    return part;
  });

  return { segments, isDeepScan: false };
}

/**
 * Automated Schema-Driven Webhook Payload Anonymization & Field Masking Policy Engine.
 *
 * Allows subscribers to attach declarative field-level data masking policies:
 * - REDACT: replaces value with '[REDACTED]' or custom string.
 * - SHA256_SALTED: deterministic salted SHA-256 hash enabling analytics correlation without cleartext leak.
 * - TRUNCATE: preserves prefix & suffix (e.g. Stellar address 'GD...7B').
 * - OMIT: removes key/property completely from the payload.
 */
export class PayloadMaskingEngine {
  private rules: MaskingRule[] = [];
  private defaultSalt: string;
  private truncateDefaults: Required<TruncateOptions>;
  private redactDefault: string;

  constructor(config?: MaskingConfig | MaskingRule[]) {
    if (Array.isArray(config)) {
      this.rules = [...config];
      this.defaultSalt = DEFAULT_SYSTEM_SALT;
      this.truncateDefaults = { ...DEFAULT_TRUNCATE_OPTIONS };
      this.redactDefault = DEFAULT_REDACT_PLACEHOLDER;
    } else if (config) {
      this.rules = config.rules ? [...config.rules] : [];
      this.defaultSalt = config.defaultSalt || config.deterministicSecret || DEFAULT_SYSTEM_SALT;
      this.truncateDefaults = {
        prefixLength: config.truncateDefaults?.prefixLength ?? DEFAULT_TRUNCATE_OPTIONS.prefixLength,
        suffixLength: config.truncateDefaults?.suffixLength ?? DEFAULT_TRUNCATE_OPTIONS.suffixLength,
        separator: config.truncateDefaults?.separator ?? DEFAULT_TRUNCATE_OPTIONS.separator,
      };
      this.redactDefault = config.redactDefault || DEFAULT_REDACT_PLACEHOLDER;
    } else {
      this.defaultSalt = DEFAULT_SYSTEM_SALT;
      this.truncateDefaults = { ...DEFAULT_TRUNCATE_OPTIONS };
      this.redactDefault = DEFAULT_REDACT_PLACEHOLDER;
    }
  }

  /**
   * Adds a masking rule to this engine instance.
   */
  public addRule(rule: MaskingRule): this {
    if (rule && rule.path && rule.policy) {
      this.rules.push(rule);
    }
    return this;
  }

  /**
   * Adds multiple masking rules to this engine instance.
   */
  public addRules(rules: MaskingRule[]): this {
    if (Array.isArray(rules)) {
      for (const r of rules) {
        this.addRule(r);
      }
    }
    return this;
  }

  /**
   * Clears all configured rules.
   */
  public clearRules(): this {
    this.rules = [];
    return this;
  }

  /**
   * Sets the default deterministic salt / secret for SHA-256 hashing.
   */
  public setSalt(salt: string): this {
    if (salt) {
      this.defaultSalt = salt;
    }
    return this;
  }

  /**
   * Returns current configured rules.
   */
  public getRules(): MaskingRule[] {
    return [...this.rules];
  }

  /**
   * Checks if any rules are active.
   */
  public hasRules(): boolean {
    return this.rules.length > 0;
  }

  /**
   * Applies configured or provided masking rules to an input payload.
   * Returns a fresh, deep-cloned object with masked fields. Original is untouched.
   */
  public mask<T = any>(payload: T, overrideRules?: MaskingRule[] | MaskingConfig): T {
    if (payload === null || payload === undefined) {
      return payload;
    }

    // Resolve rules to apply
    let rulesToApply: MaskingRule[] = this.rules;
    let customSalt = this.defaultSalt;

    if (Array.isArray(overrideRules)) {
      rulesToApply = overrideRules;
    } else if (overrideRules && typeof overrideRules === 'object') {
      if (Array.isArray(overrideRules.rules)) {
        rulesToApply = overrideRules.rules;
      }
      if (overrideRules.defaultSalt || overrideRules.deterministicSecret) {
        customSalt = overrideRules.defaultSalt || overrideRules.deterministicSecret || customSalt;
      }
    }

    if (!rulesToApply || rulesToApply.length === 0) {
      return deepClone(payload);
    }

    const cloned = deepClone(payload);

    for (const rule of rulesToApply) {
      if (!rule || !rule.path || !rule.policy) continue;
      this.applyRule(cloned, rule, customSalt);
    }

    return cloned;
  }

  /**
   * Masks a JSON string and returns the resulting masked JSON string.
   */
  public maskJson(jsonString: string, overrideRules?: MaskingRule[] | MaskingConfig): string {
    if (!jsonString || typeof jsonString !== 'string') {
      return jsonString;
    }
    try {
      const parsed = JSON.parse(jsonString);
      const masked = this.mask(parsed, overrideRules);
      return JSON.stringify(masked);
    } catch {
      return jsonString;
    }
  }

  /**
   * Internal method applying a single rule across the target object structure.
   */
  private applyRule(target: any, rule: MaskingRule, defaultSalt: string): void {
    if (target === null || typeof target !== 'object') {
      return;
    }

    const { segments, isDeepScan, deepScanKey } = parsePath(rule.path);

    if (isDeepScan && deepScanKey) {
      this.applyDeepScan(target, deepScanKey, rule, defaultSalt);
      return;
    }

    if (segments.length === 0) {
      return;
    }

    this.traverseAndApply(target, segments, rule, defaultSalt);
  }

  /**
   * Recursively traverses object/array structure according to parsed path segments.
   */
  private traverseAndApply(
    current: any,
    segments: PathSegment[],
    rule: MaskingRule,
    defaultSalt: string
  ): void {
    if (current === null || typeof current !== 'object') {
      return;
    }

    const [head, ...tail] = segments;
    const policy = (rule.policy || '').toUpperCase() as MaskingPolicy;

    // Base case: we are at the target segment
    if (tail.length === 0) {
      if (head === '*') {
        if (Array.isArray(current)) {
          if (policy === 'OMIT') {
            current.length = 0;
          } else {
            for (let i = 0; i < current.length; i++) {
              current[i] = this.transformValue(current[i], rule, defaultSalt);
            }
          }
        } else if (typeof current === 'object' && current !== null) {
          if (policy === 'OMIT') {
            for (const key of Object.keys(current)) {
              delete current[key];
            }
          } else {
            for (const key of Object.keys(current)) {
              current[key] = this.transformValue(current[key], rule, defaultSalt);
            }
          }
        }
      } else if (typeof head === 'number') {
        if (Array.isArray(current) && head >= 0 && head < current.length) {
          if (policy === 'OMIT') {
            current.splice(head, 1);
          } else {
            current[head] = this.transformValue(current[head], rule, defaultSalt);
          }
        }
      } else {
        // String key
        if (head in current) {
          if (policy === 'OMIT') {
            delete current[head];
          } else {
            current[head] = this.transformValue(current[head], rule, defaultSalt);
          }
        }
      }
      return;
    }

    // Recursive traversal case
    if (head === '*') {
      if (Array.isArray(current)) {
        for (const item of current) {
          if (item !== null && typeof item === 'object') {
            this.traverseAndApply(item, tail, rule, defaultSalt);
          }
        }
      } else if (typeof current === 'object' && current !== null) {
        for (const val of Object.values(current)) {
          if (val !== null && typeof val === 'object') {
            this.traverseAndApply(val, tail, rule, defaultSalt);
          }
        }
      }
    } else if (typeof head === 'number') {
      if (Array.isArray(current) && head >= 0 && head < current.length) {
        this.traverseAndApply(current[head], tail, rule, defaultSalt);
      }
    } else {
      if (head in current && current[head] !== null && typeof current[head] === 'object') {
        this.traverseAndApply(current[head], tail, rule, defaultSalt);
      }
    }
  }

  /**
   * Applies rule to every property matching `key` anywhere in the nested object tree.
   */
  private applyDeepScan(current: any, targetKey: string, rule: MaskingRule, defaultSalt: string): void {
    if (current === null || typeof current !== 'object') {
      return;
    }

    const policy = (rule.policy || '').toUpperCase() as MaskingPolicy;

    if (Array.isArray(current)) {
      for (const item of current) {
        this.applyDeepScan(item, targetKey, rule, defaultSalt);
      }
      return;
    }

    for (const key of Object.keys(current)) {
      if (key === targetKey) {
        if (policy === 'OMIT') {
          delete current[key];
        } else {
          current[key] = this.transformValue(current[key], rule, defaultSalt);
        }
      } else if (typeof current[key] === 'object' && current[key] !== null) {
        this.applyDeepScan(current[key], targetKey, rule, defaultSalt);
      }
    }
  }

  /**
   * Transforms an individual value according to the specified policy.
   */
  private transformValue(value: unknown, rule: MaskingRule, defaultSalt: string): unknown {
    const policy = (rule.policy || '').toUpperCase() as MaskingPolicy;

    switch (policy) {
      case 'REDACT':
        return rule.redactValue ?? this.redactDefault;

      case 'SHA256_SALTED': {
        const salt = rule.salt || defaultSalt || this.defaultSalt;
        return PayloadMaskingEngine.sha256Salted(value, salt);
      }

      case 'TRUNCATE': {
        const opts = {
          prefixLength: rule.truncateOptions?.prefixLength ?? this.truncateDefaults.prefixLength,
          suffixLength: rule.truncateOptions?.suffixLength ?? this.truncateDefaults.suffixLength,
          separator: rule.truncateOptions?.separator ?? this.truncateDefaults.separator,
        };
        return PayloadMaskingEngine.truncate(value, opts);
      }

      case 'OMIT':
        // Handled in caller via deletion/splice; if reached directly, return undefined
        return undefined;

      default:
        return value;
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Static Helper Methods
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Convenient static masking method.
   */
  public static mask<T = any>(
    payload: T,
    rulesOrConfig?: MaskingRule[] | MaskingConfig | null,
    options?: Partial<MaskingConfig>
  ): T {
    const engine = new PayloadMaskingEngine(options as MaskingConfig);
    if (!rulesOrConfig) {
      return deepClone(payload);
    }
    return engine.mask(payload, rulesOrConfig);
  }

  /**
   * REDACT policy implementation.
   * Replaces value with placeholder (default: '[REDACTED]').
   */
  public static redact(_value?: unknown, customValue?: string): string {
    return customValue ?? DEFAULT_REDACT_PLACEHOLDER;
  }

  /**
   * SHA256_SALTED policy implementation.
   * Deterministic salted cryptographic hash using SHA-256.
   *
   * Formula: SHA-256(salt + ":" + stringValue)
   * Deterministic: produces identical output for identical value and salt,
   * enabling analytics endpoints to correlate repeat counterparties/addresses.
   */
  public static sha256Salted(value: unknown, salt?: string): string {
    const activeSalt = salt || DEFAULT_SYSTEM_SALT;
    const strVal =
      value === null || value === undefined
        ? ''
        : typeof value === 'object'
        ? JSON.stringify(value)
        : String(value);

    return crypto.createHash('sha256').update(`${activeSalt}:${strVal}`).digest('hex');
  }

  /**
   * TRUNCATE policy implementation.
   * Preserves prefix and suffix characters with separator (e.g. 'GD...7B').
   */
  public static truncate(value: unknown, options?: TruncateOptions): string {
    if (value === null || value === undefined) {
      return '';
    }

    const str = String(value);
    const prefixLength = options?.prefixLength ?? DEFAULT_TRUNCATE_OPTIONS.prefixLength;
    const suffixLength = options?.suffixLength ?? DEFAULT_TRUNCATE_OPTIONS.suffixLength;
    const separator = options?.separator ?? DEFAULT_TRUNCATE_OPTIONS.separator;

    if (str.length <= prefixLength + suffixLength) {
      return str;
    }

    const prefix = str.slice(0, prefixLength);
    const suffix = str.slice(-suffixLength);
    return `${prefix}${separator}${suffix}`;
  }

  /**
   * Extracts masking rules from a webhook entity or configuration string/object.
   *
   * Supports:
   * - webhook.maskingRules (array)
   * - JSON-encoded payloadTemplate: e.g. '{"maskingRules": [...], "template": "..."}'
   * - JSON array of rules
   */
  public static extractRules(webhook: any): MaskingRule[] | null {
    if (!webhook) return null;

    if (Array.isArray(webhook)) {
      return webhook;
    }

    if (Array.isArray(webhook.maskingRules)) {
      return webhook.maskingRules;
    }

    if (Array.isArray(webhook.rules)) {
      return webhook.rules;
    }

    // Check payloadTemplate if it contains JSON configuration
    if (typeof webhook.payloadTemplate === 'string' && webhook.payloadTemplate.trim().startsWith('{')) {
      try {
        const parsed = JSON.parse(webhook.payloadTemplate);
        if (Array.isArray(parsed.maskingRules)) {
          return parsed.maskingRules;
        }
        if (Array.isArray(parsed.maskRules)) {
          return parsed.maskRules;
        }
        if (Array.isArray(parsed.rules)) {
          return parsed.rules;
        }
      } catch {
        // Not a valid JSON config, standard template string
      }
    } else if (typeof webhook.payloadTemplate === 'object' && webhook.payloadTemplate !== null) {
      if (Array.isArray(webhook.payloadTemplate.maskingRules)) {
        return webhook.payloadTemplate.maskingRules;
      }
      if (Array.isArray(webhook.payloadTemplate.rules)) {
        return webhook.payloadTemplate.rules;
      }
    }

    return null;
  }

  /**
   * Helper that masks a webhook payload prior to cryptographic signature generation.
   * If the webhook contains masking rules, applies them; otherwise returns cloned payload.
   */
  public static maskWebhookPayload<T = any>(payload: T, webhook: any): T {
    const rules = PayloadMaskingEngine.extractRules(webhook);
    if (!rules || rules.length === 0) {
      return payload;
    }
    return PayloadMaskingEngine.mask(payload, rules);
  }
}

/** Default singleton instance of PayloadMaskingEngine */
export const payloadMaskingEngine = new PayloadMaskingEngine();
