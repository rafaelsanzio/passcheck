
import type { Issue, PassCheckConfig } from '../client';

export class RequirementsList {
    private list: HTMLElement;
    private requirements: { id: string; label: string; rule: string; configKey?: keyof PassCheckConfig }[];
    private config: PassCheckConfig;

    constructor(container: HTMLElement, initialConfig: PassCheckConfig) {
        this.list = document.createElement('ul');
        this.list.className = 'requirements-list';
        container.appendChild(this.list);
        this.config = initialConfig || {};

        this.requirements = [
            { id: 'length', label: 'Minimum Length', rule: 'RULE_TOO_SHORT', configKey: 'minLength' },
            { id: 'upper', label: 'Uppercase', rule: 'RULE_NO_UPPER', configKey: 'requireUpper' },
            { id: 'lower', label: 'Lowercase', rule: 'RULE_NO_LOWER', configKey: 'requireLower' },
            { id: 'digit', label: 'Number', rule: 'RULE_NO_DIGIT', configKey: 'requireDigit' },
            { id: 'symbol', label: 'Symbol', rule: 'RULE_NO_SYMBOL', configKey: 'requireSymbol' },
        ];

        this.render();
    }

    private render() {
        // Filter requirements based on config
        const activeReqs = this.requirements.filter(req => {
            if (!req.configKey) return true;
            const val = this.config[req.configKey];
            if (val === undefined) return true;

            if (req.id === 'length') return (val as number) > 0;
            return !!val;
        });

        this.list.innerHTML = activeReqs
            .map(
                (req) => {
                    const label = req.id === 'length' ? `${this.config.minLength || 8}+ Characters` : req.label;
                    return `
                      <li class="requirement-item" id="req-${req.rule}">
                        <span class="requirement-icon">
                          <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="20 6 9 17 4 12"></polyline>
                          </svg>
                        </span>
                        ${label}
                      </li>
                    `;
                }
            )
            .join('');
    }

    update(issues: Issue[], config: PassCheckConfig) {
        // If config changed significantly, we might want to re-render, but usually we just update status
        // The label for length might need update
        if (config.minLength !== this.config.minLength) {
            this.config = config;
            this.render();
        }

        this.requirements.forEach((req) => {
            // If the rule is NOT in the issues list, it is met
            const isMet = !issues.some((i) => i.code === req.rule);
            const el = this.list.querySelector(`#req-${req.rule}`);
            if (el) {
                if (isMet) {
                    el.classList.add('met');
                } else {
                    el.classList.remove('met');
                }
            }
        });
    }

    updateConfig(config: PassCheckConfig) {
        this.config = config;
        this.render();
    }

    reset() {
        this.render();
        this.list.querySelectorAll('.requirement-item').forEach(el => el.classList.remove('met'));
    }
}
