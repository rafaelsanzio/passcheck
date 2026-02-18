
import type { PassCheckConfig } from '../client';

export class ConfigPanel {
  private container: HTMLElement;
  private config: PassCheckConfig;
  private onChange: (config: PassCheckConfig) => void;

  constructor(container: HTMLElement, initialConfig: PassCheckConfig, onChange: (config: PassCheckConfig) => void) {
    this.container = document.createElement('div');
    this.container.className = 'config-panel';
    this.config = { ...initialConfig };
    this.onChange = onChange;

    this.render();
    container.appendChild(this.container);
  }

  private render() {
    this.container.innerHTML = `
      <div class="config-header">
        <h3>Configuration</h3>
      </div>
      
      <!-- General Section -->
      <div class="config-section">
        <div class="config-row-select">
            <label for="cfg-preset" class="row-label">Preset</label>
            <div class="select-wrapper">
                <select id="cfg-preset">
                <option value="">Custom</option>
                <option value="nist" ${this.config.preset === 'nist' ? 'selected' : ''}>NIST</option>
                <option value="pci" ${this.config.preset === 'pci' ? 'selected' : ''}>PCI-DSS</option>
                <option value="owasp" ${this.config.preset === 'owasp' ? 'selected' : ''}>OWASP</option>
                <option value="enterprise" ${this.config.preset === 'enterprise' ? 'selected' : ''}>Enterprise</option>
                <option value="userfriendly" ${this.config.preset === 'userfriendly' ? 'selected' : ''}>User Friendly</option>
                </select>
                <svg class="select-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
            </div>
        </div>
        
         <label class="toggle-switch-wrapper" style="margin-top: 1rem;">
            <input type="checkbox" id="cfg-hibp" ${this.config.useHibp ? 'checked' : ''}>
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
                <label class="toggle-switch-wrapper">
                    <input type="checkbox" id="cfg-upper" ${this.config.requireUpper ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label-text">Uppercase</span>
                </label>
                <label class="toggle-switch-wrapper">
                    <input type="checkbox" id="cfg-lower" ${this.config.requireLower ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label-text">Lowercase</span>
                </label>
                <label class="toggle-switch-wrapper">
                    <input type="checkbox" id="cfg-digit" ${this.config.requireDigit ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label-text">Digits</span>
                </label>
                <label class="toggle-switch-wrapper">
                    <input type="checkbox" id="cfg-symbol" ${this.config.requireSymbol ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label-text">Symbols</span>
                </label>
            </div>
            <div class="config-row">
                <label for="cfg-min-len" class="row-label">Minimum Length</label>
                <input type="number" id="cfg-min-len" class="input-number" value="${this.config.minLength || 8}" min="1" max="128">
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
                <input type="number" id="cfg-max-repeats" class="input-number" value="${this.config.maxRepeats || 0}" min="0" title="0 to disable">
            </div>
             <div class="config-row">
                <label for="cfg-pat-len" class="row-label">Pattern Min Length</label>
                <input type="number" id="cfg-pat-len" class="input-number" value="${this.config.patternMinLength || 3}" min="2">
            </div>
             <label class="toggle-switch-wrapper" style="margin-top: 1rem;">
                <input type="checkbox" id="cfg-disable-leet" ${this.config.disableLeet ? 'checked' : ''}>
                <span class="toggle-slider"></span>
                <span class="toggle-label-text">Disable L33T Speak Detection</span>
            </label>
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

    this.bindNumber('cfg-min-len', 'minLength');
    this.bindNumber('cfg-max-repeats', 'maxRepeats');
    this.bindNumber('cfg-pat-len', 'patternMinLength');

    this.bindSelect('cfg-preset', 'preset');

    this.bindTextarea('cfg-custom-pw', 'customPasswords');
    this.bindTextarea('cfg-custom-words', 'customWords');
    this.bindTextarea('cfg-context-words', 'contextWords');
  }

  private bindCheckbox(id: string, key: keyof PassCheckConfig) {
    const el = this.container.querySelector(`#${id}`) as HTMLInputElement;
    el.addEventListener('change', () => {
      (this.config as any)[key] = el.checked;
      this.onChange(this.config);
    });
  }

  private bindNumber(id: string, key: keyof PassCheckConfig) {
    const el = this.container.querySelector(`#${id}`) as HTMLInputElement;
    el.addEventListener('change', () => {
      const val = parseInt(el.value, 10);
      (this.config as any)[key] = isNaN(val) ? undefined : val;
      this.onChange(this.config);
    });
  }

  private bindSelect(id: string, key: keyof PassCheckConfig) {
    const el = this.container.querySelector(`#${id}`) as HTMLSelectElement;
    el.addEventListener('change', () => {
      const val = el.value;
      if (val) {
        (this.config as any)[key] = val;
      } else {
        delete (this.config as any)[key];
      }
      this.onChange(this.config);
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
