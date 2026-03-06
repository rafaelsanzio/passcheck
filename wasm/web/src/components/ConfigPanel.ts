
import type { PassCheckConfig } from '../client';
import { applyPolicy, isFieldLocked, getActivePolicy } from '../policies';

export class ConfigPanel {
  private container: HTMLElement;
  private config: PassCheckConfig;
  private onChange: (config: PassCheckConfig) => void;

  constructor(container: HTMLElement, initialConfig: PassCheckConfig, onChange: (config: PassCheckConfig) => void) {
    this.container = document.createElement('div');
    this.container.className = 'config-panel';
    // Apply policy if preset is set in initial config
    this.config = applyPolicy(initialConfig.preset, initialConfig);
    this.onChange = onChange;

    this.render();
    container.appendChild(this.container);
  }

  private render() {
    const activePolicy = getActivePolicy(this.config.preset);
    const isPolicyMode = !!this.config.preset;

    this.container.innerHTML = `
      <div class="config-header">
        <h3>Policy Configuration</h3>
        ${activePolicy ? `
          <div class="active-policy-badge">
            <span class="policy-name">${activePolicy.name}</span>
            <span class="policy-description">${activePolicy.description}</span>
          </div>
        ` : `
          <div class="active-policy-badge">
            <span class="policy-name">Custom Policy</span>
            <span class="policy-description">Configure your own password requirements</span>
          </div>
        `}
      </div>
      
      <!-- Policy Selection -->
      <div class="config-section">
        <div class="config-row-select">
            <label for="cfg-preset" class="row-label">Select Policy</label>
            <div class="select-wrapper">
                <select id="cfg-preset">
                <option value="">Custom</option>
                <option value="nist" ${this.config.preset === 'nist' ? 'selected' : ''}>NIST SP 800-63B</option>
                <option value="pci" ${this.config.preset === 'pci' ? 'selected' : ''}>PCI DSS 4.0</option>
                <option value="owasp" ${this.config.preset === 'owasp' ? 'selected' : ''}>OWASP</option>
                <option value="enterprise" ${this.config.preset === 'enterprise' ? 'selected' : ''}>Enterprise</option>
                <option value="userfriendly" ${this.config.preset === 'userfriendly' ? 'selected' : ''}>User Friendly</option>
                </select>
                <svg class="select-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
            </div>
        </div>
        ${isPolicyMode ? `
          <p class="policy-locked-notice">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" style="width: 1rem; height: 1rem; display: inline-block; vertical-align: middle; margin-right: 0.5rem;">
              <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
            </svg>
            Policy settings are locked. Select "Custom" to modify individual parameters.
          </p>
        ` : ''}
        
         <label class="toggle-switch-wrapper" style="margin-top: 1rem;">
            <input type="checkbox" id="cfg-hibp" ${this.config.useHibp ? 'checked' : ''} ${isFieldLocked(this.config.preset, 'useHibp') ? 'disabled' : ''}>
            <span class="toggle-slider"></span>
            <span class="toggle-label-text">Check Breached Passwords (HIBP)</span>
          </label>
      </div>

      <!-- Basic Rules -->
      <details open class="config-details">
        <summary>
            <span>Basic Rules</span>
            <svg class="chevron-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
            </svg>
        </summary>
        <div class="config-content">
            <div class="config-grid">
                <label class="toggle-switch-wrapper ${isFieldLocked(this.config.preset, 'requireUpper') ? 'locked' : ''}">
                    <input type="checkbox" id="cfg-upper" ${this.config.requireUpper ? 'checked' : ''} ${isFieldLocked(this.config.preset, 'requireUpper') ? 'disabled' : ''}>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label-text">Uppercase</span>
                </label>
                <label class="toggle-switch-wrapper ${isFieldLocked(this.config.preset, 'requireLower') ? 'locked' : ''}">
                    <input type="checkbox" id="cfg-lower" ${this.config.requireLower ? 'checked' : ''} ${isFieldLocked(this.config.preset, 'requireLower') ? 'disabled' : ''}>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label-text">Lowercase</span>
                </label>
                <label class="toggle-switch-wrapper ${isFieldLocked(this.config.preset, 'requireDigit') ? 'locked' : ''}">
                    <input type="checkbox" id="cfg-digit" ${this.config.requireDigit ? 'checked' : ''} ${isFieldLocked(this.config.preset, 'requireDigit') ? 'disabled' : ''}>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label-text">Digits</span>
                </label>
                <label class="toggle-switch-wrapper ${isFieldLocked(this.config.preset, 'requireSymbol') ? 'locked' : ''}">
                    <input type="checkbox" id="cfg-symbol" ${this.config.requireSymbol ? 'checked' : ''} ${isFieldLocked(this.config.preset, 'requireSymbol') ? 'disabled' : ''}>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label-text">Symbols</span>
                </label>
            </div>
            <div class="config-row">
                <label for="cfg-min-len" class="row-label">Minimum Length</label>
                <input type="number" id="cfg-min-len" class="input-number ${isFieldLocked(this.config.preset, 'minLength') ? 'locked' : ''}" 
                       value="${this.config.minLength || 8}" min="1" max="128" 
                       ${isFieldLocked(this.config.preset, 'minLength') ? 'disabled' : ''}
                       title="${isFieldLocked(this.config.preset, 'minLength') ? 'Locked by policy' : ''}">
            </div>
        </div>
      </details>

      <!-- Advanced Rules -->
      <details class="config-details">
        <summary>
            <span>Advanced Rules</span>
            <svg class="chevron-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
            </svg>
        </summary>
        <div class="config-content">
            <div class="config-row">
                <label for="cfg-max-repeats" class="row-label">Max Repeats</label>
                <input type="number" id="cfg-max-repeats" class="input-number ${isFieldLocked(this.config.preset, 'maxRepeats') ? 'locked' : ''}" 
                       value="${this.config.maxRepeats ?? (this.config.maxRepeats === 0 ? 0 : '')}" min="0" 
                       title="${isFieldLocked(this.config.preset, 'maxRepeats') ? 'Locked by policy' : '0 to disable'}"
                       ${isFieldLocked(this.config.preset, 'maxRepeats') ? 'disabled' : ''}>
            </div>
             <div class="config-row">
                <label for="cfg-pat-len" class="row-label">Pattern Min Length</label>
                <input type="number" id="cfg-pat-len" class="input-number ${isFieldLocked(this.config.preset, 'patternMinLength') ? 'locked' : ''}" 
                       value="${this.config.patternMinLength ?? 3}" min="2"
                       ${isFieldLocked(this.config.preset, 'patternMinLength') ? 'disabled' : ''}
                       title="${isFieldLocked(this.config.preset, 'patternMinLength') ? 'Locked by policy' : ''}">
            </div>
             <label class="toggle-switch-wrapper" style="margin-top: 1rem;">
                <input type="checkbox" id="cfg-disable-leet" ${this.config.disableLeet ? 'checked' : ''}>
                <span class="toggle-slider"></span>
                <span class="toggle-label-text">Disable L33T Speak Detection</span>
            </label>
        </div>
      </details>

      <!-- Passphrase Mode -->
      <details class="config-details">
        <summary>
            <span>Passphrase Mode</span>
            <svg class="chevron-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
            </svg>
        </summary>
        <div class="config-content">
            <label class="toggle-switch-wrapper">
                <input type="checkbox" id="cfg-passphrase-mode" ${this.config.passphraseMode ? 'checked' : ''}>
                <span class="toggle-slider"></span>
                <span class="toggle-label-text">Enable Passphrase-Friendly Scoring</span>
            </label>
            <p class="config-help-text" style="margin-top: 0.5rem; margin-bottom: 1rem; color: var(--text-secondary); font-size: 0.875rem;">
                When enabled, multi-word passphrases (detected via spaces, hyphens, camelCase, etc.) use word-based entropy and reduced dictionary penalties.
            </p>
            <div class="config-row">
                <label for="cfg-min-words" class="row-label">Minimum Words</label>
                <input type="number" id="cfg-min-words" class="input-number" value="${this.config.minWords || 4}" min="1" max="20" title="Minimum distinct words to consider a passphrase">
            </div>
            <div class="config-row">
                <label for="cfg-word-dict-size" class="row-label">Word Dictionary Size</label>
                <input type="number" id="cfg-word-dict-size" class="input-number" value="${this.config.wordDictSize || 7776}" min="2" title="Assumed dictionary size for entropy calculation (default: 7776 for diceware)">
            </div>
        </div>
      </details>

      <!-- Entropy Mode -->
      <details class="config-details">
        <summary>
            <span>Entropy Calculation</span>
            <svg class="chevron-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
            </svg>
        </summary>
        <div class="config-content">
            <div class="config-row-select">
                <label for="cfg-entropy-mode" class="row-label">Entropy Mode</label>
                <div class="select-wrapper">
                    <select id="cfg-entropy-mode">
                        <option value="simple" ${this.config.entropyMode === 'simple' || !this.config.entropyMode ? 'selected' : ''}>Simple</option>
                        <option value="advanced" ${this.config.entropyMode === 'advanced' ? 'selected' : ''}>Advanced</option>
                        <option value="pattern-aware" ${this.config.entropyMode === 'pattern-aware' ? 'selected' : ''}>Pattern-Aware</option>
                    </select>
                    <svg class="select-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                    </svg>
                </div>
            </div>
            <p class="config-help-text" style="margin-top: 0.5rem; color: var(--text-secondary); font-size: 0.875rem;">
                <strong>Simple:</strong> Basic character-pool × length formula.<br>
                <strong>Advanced:</strong> Reduces entropy for detected patterns (keyboard walks, sequences).<br>
                <strong>Pattern-Aware:</strong> Includes Markov-chain analysis for character transition probabilities.
            </p>
        </div>
      </details>

      <!-- Penalty Weights -->
      <details class="config-details">
        <summary>
            <span>Penalty Weights</span>
            <svg class="chevron-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
            </svg>
        </summary>
        <div class="config-content">
            <p class="config-help-text" style="margin-bottom: 1rem; color: var(--text-secondary); font-size: 0.875rem;">
                Customize penalty multipliers and entropy weight. Default is 1.0 for all. Leave empty to use defaults.
            </p>
            <div class="config-grid">
                <div class="config-row">
                    <label for="cfg-weight-rule" class="row-label">Rule Violation</label>
                    <input type="number" id="cfg-weight-rule" class="input-number" 
                           value="${this.config.penaltyWeights?.ruleViolation || ''}" 
                           min="0" step="0.1" placeholder="1.0" title="Multiplier for rule violations (length, charset, etc.)">
                </div>
                <div class="config-row">
                    <label for="cfg-weight-pattern" class="row-label">Pattern Match</label>
                    <input type="number" id="cfg-weight-pattern" class="input-number" 
                           value="${this.config.penaltyWeights?.patternMatch || ''}" 
                           min="0" step="0.1" placeholder="1.0" title="Multiplier for pattern detections (keyboard walks, sequences)">
                </div>
                <div class="config-row">
                    <label for="cfg-weight-dict" class="row-label">Dictionary Match</label>
                    <input type="number" id="cfg-weight-dict" class="input-number" 
                           value="${this.config.penaltyWeights?.dictionaryMatch || ''}" 
                           min="0" step="0.1" placeholder="1.0" title="Multiplier for dictionary matches (common passwords, words)">
                </div>
                <div class="config-row">
                    <label for="cfg-weight-context" class="row-label">Context Match</label>
                    <input type="number" id="cfg-weight-context" class="input-number" 
                           value="${this.config.penaltyWeights?.contextMatch || ''}" 
                           min="0" step="0.1" placeholder="1.0" title="Multiplier for context detections (username, email)">
                </div>
                <div class="config-row">
                    <label for="cfg-weight-hibp" class="row-label">HIBP Breach</label>
                    <input type="number" id="cfg-weight-hibp" class="input-number" 
                           value="${this.config.penaltyWeights?.hibpBreach || ''}" 
                           min="0" step="0.1" placeholder="1.0" title="Multiplier for HIBP breach database matches">
                </div>
                <div class="config-row">
                    <label for="cfg-weight-entropy" class="row-label">Entropy Weight</label>
                    <input type="number" id="cfg-weight-entropy" class="input-number" 
                           value="${this.config.penaltyWeights?.entropyWeight || ''}" 
                           min="0" step="0.1" placeholder="1.0" title="Multiplier for entropy base score (< 1.0 reduces influence, > 1.0 increases)">
                </div>
            </div>
        </div>
      </details>

      <!-- Dictionaries -->
      <details class="config-details">
        <summary>
            <span>Dictionaries</span>
            <svg class="chevron-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
            </svg>
        </summary>
        <div class="config-content">
            <div class="input-group-vertical">
                <label for="cfg-custom-pw">Blocked Passwords <span class="sub-label">(one per line)</span></label>
                <textarea id="cfg-custom-pw" rows="3" placeholder="password123\nadmin">${(this.config.customPasswords || []).join('\n')}</textarea>
            </div>
             <div class="input-group-vertical">
                <label for="cfg-custom-words">Forbidden Words <span class="sub-label">(one per line)</span></label>
                <textarea id="cfg-custom-words" rows="3" placeholder="companyname\nsecret">${(this.config.customWords || []).join('\n')}</textarea>
            </div>
             <div class="input-group-vertical">
                <label for="cfg-context-words">Context Words <span class="sub-label">(one per line)</span></label>
                <textarea id="cfg-context-words" rows="3" placeholder="username\nemail">${(this.config.contextWords || []).join('\n')}</textarea>
            </div>
        </div>
      </details>
    `;

    this.bindEvents();
  }

  private bindEvents() {
    this.bindCheckbox('cfg-upper', 'requireUpper');
    this.bindCheckbox('cfg-lower', 'requireLower');
    this.bindCheckbox('cfg-digit', 'requireDigit');
    this.bindCheckbox('cfg-symbol', 'requireSymbol');
    this.bindCheckbox('cfg-hibp', 'useHibp');
    this.bindCheckbox('cfg-disable-leet', 'disableLeet');
    this.bindCheckbox('cfg-passphrase-mode', 'passphraseMode');

    this.bindNumber('cfg-min-len', 'minLength');
    this.bindNumber('cfg-max-repeats', 'maxRepeats');
    this.bindNumber('cfg-pat-len', 'patternMinLength');
    this.bindNumber('cfg-min-words', 'minWords');
    this.bindNumber('cfg-word-dict-size', 'wordDictSize');

    this.bindSelect('cfg-preset', 'preset');
    this.bindSelect('cfg-entropy-mode', 'entropyMode');

    this.bindTextarea('cfg-custom-pw', 'customPasswords');
    this.bindTextarea('cfg-custom-words', 'customWords');
    this.bindTextarea('cfg-context-words', 'contextWords');

    this.bindPenaltyWeights();
  }

  private bindPenaltyWeights() {
    const weights = this.config.penaltyWeights || {};
    
    this.bindPenaltyWeight('cfg-weight-rule', 'ruleViolation', weights);
    this.bindPenaltyWeight('cfg-weight-pattern', 'patternMatch', weights);
    this.bindPenaltyWeight('cfg-weight-dict', 'dictionaryMatch', weights);
    this.bindPenaltyWeight('cfg-weight-context', 'contextMatch', weights);
    this.bindPenaltyWeight('cfg-weight-hibp', 'hibpBreach', weights);
    this.bindPenaltyWeight('cfg-weight-entropy', 'entropyWeight', weights);
  }

  private bindPenaltyWeight(inputId: string, key: keyof import('../client').PenaltyWeights, weights: import('../client').PenaltyWeights) {
    const el = this.container.querySelector(`#${inputId}`) as HTMLInputElement;
    if (!el) return;
    
    el.addEventListener('change', () => {
      const val = parseFloat(el.value);
      if (isNaN(val) || val === 0 || el.value.trim() === '') {
        // Remove the weight if empty or 0 (defaults to 1.0)
        delete (weights as any)[key];
      } else {
        (weights as any)[key] = val;
      }
      
      // Only create penaltyWeights object if at least one weight is set
      const hasWeights = Object.keys(weights).length > 0;
      if (hasWeights) {
        this.config.penaltyWeights = weights;
      } else {
        delete this.config.penaltyWeights;
      }
      
      this.onChange(this.config);
    });
  }

  private bindCheckbox(id: string, key: keyof PassCheckConfig) {
    const el = this.container.querySelector(`#${id}`) as HTMLInputElement;
    if (!el) return;
    
    // Always bind event, but check lock status when triggered
    el.addEventListener('change', () => {
      if (isFieldLocked(this.config.preset, key)) {
        // Revert if changed while locked
        el.checked = (this.config as any)[key] || false;
        return;
      }
      (this.config as any)[key] = el.checked;
      this.onChange(this.config);
    });
  }

  private bindNumber(id: string, key: keyof PassCheckConfig) {
    const el = this.container.querySelector(`#${id}`) as HTMLInputElement;
    if (!el) return;
    
    // Always bind event, but check lock status when triggered
    el.addEventListener('change', () => {
      if (isFieldLocked(this.config.preset, key)) {
        // Revert if changed while locked
        el.value = String((this.config as any)[key] || '');
        return;
      }
      const val = parseInt(el.value, 10);
      (this.config as any)[key] = isNaN(val) ? undefined : val;
      this.onChange(this.config);
    });
    
    // Also handle input event for real-time updates
    el.addEventListener('input', () => {
      if (isFieldLocked(this.config.preset, key)) {
        el.value = String((this.config as any)[key] || '');
      }
    });
  }

  private bindSelect(id: string, key: keyof PassCheckConfig) {
    const el = this.container.querySelector(`#${id}`) as HTMLSelectElement;
    if (!el) return;
    el.addEventListener('change', () => {
      const val = el.value;
      
      if (key === 'preset') {
        // Apply policy when preset changes
        const presetValue = val || undefined;
        // Preserve custom dictionaries and advanced settings
        const preserved = {
          customPasswords: this.config.customPasswords,
          customWords: this.config.customWords,
          contextWords: this.config.contextWords,
          passphraseMode: this.config.passphraseMode,
          minWords: this.config.minWords,
          wordDictSize: this.config.wordDictSize,
          entropyMode: this.config.entropyMode,
          penaltyWeights: this.config.penaltyWeights,
          useHibp: this.config.useHibp,
        };
        const newConfig = applyPolicy(presetValue, { ...this.config, ...preserved });
        this.config = newConfig;
        // Re-render to update locked fields and values
        this.render();
        // Notify parent of config change
        this.onChange(this.config);
      } else {
        if (val && val !== 'simple') { // 'simple' is default, so we can omit it
          (this.config as any)[key] = val;
        } else {
          delete (this.config as any)[key];
        }
        this.onChange(this.config);
      }
    });
  }

  private bindTextarea(id: string, key: keyof PassCheckConfig) {
    const el = this.container.querySelector(`#${id}`) as HTMLTextAreaElement;
    el.addEventListener('change', () => {
      const val = el.value.trim();
      const items = val.split('\n').map(s => s.trim()).filter(s => s.length > 0);
      (this.config as any)[key] = items.length > 0 ? items : undefined;
      this.onChange(this.config);
    });
  }
}
