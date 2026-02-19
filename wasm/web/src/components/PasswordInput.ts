/**
 * PasswordInput provides a modern password input field with show/hide toggle.
 * Supports passphrases (spaces and special characters) and provides
 * proper accessibility features.
 */
export class PasswordInput {
    private container: HTMLElement;
    public input: HTMLInputElement;
    private toggleBtn: HTMLButtonElement;
    private isVisible: boolean = false;

    constructor(container: HTMLElement, onChange: (value: string) => void) {
        this.container = this.createContainer();
        this.input = this.createInput();
        this.toggleBtn = this.createToggleButton();

        this.setupEventListeners(onChange);
        this.container.appendChild(this.input);
        this.container.appendChild(this.toggleBtn);
        container.appendChild(this.container);
    }

    private createContainer(): HTMLElement {
        const container = document.createElement('div');
        container.className = 'password-input-group';
        return container;
    }

    private createInput(): HTMLInputElement {
        const input = document.createElement('input');
        input.type = 'password';
        input.className = 'password-input';
        input.placeholder = 'Enter password or passphrase...';
        input.setAttribute('aria-label', 'Password or passphrase');
        input.setAttribute('aria-describedby', 'password-toggle-description');
        input.setAttribute('autocomplete', 'new-password'); // Helps password managers
        input.setAttribute('spellcheck', 'false'); // Disable spellcheck for passwords
        // Allow spaces for passphrases - HTML password inputs already support this
        return input;
    }

    private createToggleButton(): HTMLButtonElement {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'password-toggle-btn';
        button.setAttribute('aria-label', 'Show password');
        button.setAttribute('aria-pressed', 'false');
        button.setAttribute('aria-describedby', 'password-toggle-description');
        button.setAttribute('id', 'password-toggle-description');
        button.innerHTML = this.getEyeIcon(false);
        return button;
    }

    private getEyeIcon(visible: boolean): string {
        if (visible) {
            // Eye with slash (hide icon)
            return `
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                    <line x1="1" y1="1" x2="23" y2="23"></line>
                </svg>
            `;
        } else {
            // Eye icon (show icon)
            return `
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                </svg>
            `;
        }
    }

    private setupEventListeners(onChange: (value: string) => void): void {
        // Toggle password visibility
        this.toggleBtn.addEventListener('click', (e) => {
            e.preventDefault();
            this.toggleVisibility();
        });

        // Handle input changes
        this.input.addEventListener('input', () => {
            onChange(this.input.value);
        });

        // Prevent form submission on Enter (optional, but good practice)
        this.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
            }
        });
    }

    private toggleVisibility(): void {
        this.isVisible = !this.isVisible;
        
        if (this.isVisible) {
            this.input.type = 'text';
            this.toggleBtn.setAttribute('aria-label', 'Hide password');
            this.toggleBtn.setAttribute('aria-pressed', 'true');
            this.toggleBtn.innerHTML = this.getEyeIcon(true);
            this.input.setAttribute('autocomplete', 'off'); // Disable autocomplete when visible
        } else {
            this.input.type = 'password';
            this.toggleBtn.setAttribute('aria-label', 'Show password');
            this.toggleBtn.setAttribute('aria-pressed', 'false');
            this.toggleBtn.innerHTML = this.getEyeIcon(false);
            this.input.setAttribute('autocomplete', 'new-password');
        }
    }

    getValue(): string {
        return this.input.value;
    }

    /**
     * Focuses the password input field.
     */
    focus(): void {
        this.input.focus();
    }

    /**
     * Clears the password input field.
     */
    clear(): void {
        this.input.value = '';
        // Reset visibility state
        if (this.isVisible) {
            this.toggleVisibility();
        }
    }
}
