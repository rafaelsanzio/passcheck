/**
 * Policy definitions matching Go presets.
 * When a policy is selected, these settings are enforced and locked.
 */
import type { PassCheckConfig } from './client';

export interface PolicyDefinition {
    name: string;
    description: string;
    config: PassCheckConfig;
    lockedFields: Set<keyof PassCheckConfig>;
}

export const POLICIES: Record<string, PolicyDefinition> = {
    nist: {
        name: 'NIST SP 800-63B',
        description: 'NIST guidelines emphasize password length over complexity. No composition rules required.',
        config: {
            preset: 'nist',
            minLength: 8,
            requireUpper: false,
            requireLower: false,
            requireDigit: false,
            requireSymbol: false,
            maxRepeats: 99, // Effectively unlimited
            patternMinLength: 99, // Effectively disabled
            maxIssues: 5,
            disableLeet: false,
            useHibp: true, // NIST recommends breach checking
        },
        lockedFields: new Set([
            'minLength',
            'requireUpper',
            'requireLower',
            'requireDigit',
            'requireSymbol',
            'maxRepeats',
            'patternMinLength',
        ]),
    },
    pci: {
        name: 'PCI DSS 4.0',
        description: 'Payment Card Industry Data Security Standard v4.0. Strict complexity requirements for payment systems.',
        config: {
            preset: 'pci',
            minLength: 12,
            requireUpper: true,
            requireLower: true,
            requireDigit: true,
            requireSymbol: true,
            maxRepeats: 3,
            patternMinLength: 4,
            maxIssues: 5,
            disableLeet: false,
        },
        lockedFields: new Set([
            'minLength',
            'requireUpper',
            'requireLower',
            'requireDigit',
            'requireSymbol',
            'maxRepeats',
            'patternMinLength',
        ]),
    },
    owasp: {
        name: 'OWASP',
        description: 'OWASP recommendations for web applications. Balanced security and usability.',
        config: {
            preset: 'owasp',
            minLength: 10,
            requireUpper: true,
            requireLower: true,
            requireDigit: true,
            requireSymbol: false, // Optional for better UX
            maxRepeats: 3,
            patternMinLength: 4,
            maxIssues: 5,
            disableLeet: false,
        },
        lockedFields: new Set([
            'minLength',
            'requireUpper',
            'requireLower',
            'requireDigit',
            'requireSymbol',
            'maxRepeats',
            'patternMinLength',
        ]),
    },
    enterprise: {
        name: 'Enterprise',
        description: 'High-security configuration for enterprise environments. Maximum security controls.',
        config: {
            preset: 'enterprise',
            minLength: 14,
            requireUpper: true,
            requireLower: true,
            requireDigit: true,
            requireSymbol: true,
            maxRepeats: 2, // Stricter than default
            patternMinLength: 3, // More aggressive
            maxIssues: 10,
            disableLeet: false,
        },
        lockedFields: new Set([
            'minLength',
            'requireUpper',
            'requireLower',
            'requireDigit',
            'requireSymbol',
            'maxRepeats',
            'patternMinLength',
        ]),
    },
    userfriendly: {
        name: 'User Friendly',
        description: 'Consumer-focused configuration prioritizing user experience while maintaining reasonable security.',
        config: {
            preset: 'userfriendly',
            minLength: 10,
            requireUpper: false,
            requireLower: true,
            requireDigit: true,
            requireSymbol: false,
            maxRepeats: 4, // More lenient
            patternMinLength: 5, // Less aggressive
            maxIssues: 3,
            disableLeet: false,
        },
        lockedFields: new Set([
            'minLength',
            'requireUpper',
            'requireLower',
            'requireDigit',
            'requireSymbol',
            'maxRepeats',
            'patternMinLength',
        ]),
    },
};

/**
 * Applies a policy to the config, merging with existing custom settings.
 */
export function applyPolicy(preset: string | undefined, currentConfig: PassCheckConfig): PassCheckConfig {
    if (!preset || !POLICIES[preset]) {
        // Custom mode - return config as-is, remove preset
        const custom = { ...currentConfig };
        delete custom.preset;
        return custom;
    }

    const policy = POLICIES[preset];
    
    // Start with policy config (this sets all locked fields)
    const applied: PassCheckConfig = {
        ...policy.config,
    };

    // Preserve custom dictionaries and context words (not locked by policy)
    if (currentConfig.customPasswords) {
        applied.customPasswords = currentConfig.customPasswords;
    }
    if (currentConfig.customWords) {
        applied.customWords = currentConfig.customWords;
    }
    if (currentConfig.contextWords) {
        applied.contextWords = currentConfig.contextWords;
    }
    // Preserve advanced settings that aren't locked
    if (currentConfig.passphraseMode !== undefined) {
        applied.passphraseMode = currentConfig.passphraseMode;
    }
    if (currentConfig.minWords !== undefined) {
        applied.minWords = currentConfig.minWords;
    }
    if (currentConfig.wordDictSize !== undefined) {
        applied.wordDictSize = currentConfig.wordDictSize;
    }
    if (currentConfig.entropyMode !== undefined) {
        applied.entropyMode = currentConfig.entropyMode;
    }
    if (currentConfig.penaltyWeights !== undefined) {
        applied.penaltyWeights = currentConfig.penaltyWeights;
    }
    // Preserve HIBP setting if not locked (only NIST locks it)
    if (!policy.lockedFields.has('useHibp') && currentConfig.useHibp !== undefined) {
        applied.useHibp = currentConfig.useHibp;
    }

    return applied;
}

/**
 * Checks if a field is locked by the current policy.
 */
export function isFieldLocked(preset: string | undefined, field: keyof PassCheckConfig): boolean {
    if (!preset || !POLICIES[preset]) {
        return false;
    }
    return POLICIES[preset].lockedFields.has(field);
}

/**
 * Gets the active policy definition.
 */
export function getActivePolicy(preset: string | undefined): PolicyDefinition | null {
    if (!preset || !POLICIES[preset]) {
        return null;
    }
    return POLICIES[preset];
}
