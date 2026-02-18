
export class PasswordInput {
    private container: HTMLElement;
    public input: HTMLInputElement;
    private toggleBtn: HTMLButtonElement;

    constructor(container: HTMLElement, onChange: (value: string) => void) {
        this.container = document.createElement('div');
        this.container.className = 'input-group';

        this.input = document.createElement('input');
        this.input.type = 'password';
        this.input.placeholder = 'Enter your password...';
        this.input.setAttribute('aria-label', 'Password');

        this.toggleBtn = document.createElement('button');
        this.toggleBtn.type = 'button';
        this.toggleBtn.textContent = 'Show';
        this.toggleBtn.style.position = 'absolute';
        this.toggleBtn.style.right = '10px';
        this.toggleBtn.style.top = '50%';
        this.toggleBtn.style.transform = 'translateY(-50%)';
        this.toggleBtn.style.background = 'none';
        this.toggleBtn.style.border = 'none';
        this.toggleBtn.style.color = 'var(--text-secondary)';
        this.toggleBtn.style.fontSize = '0.8rem';
        this.toggleBtn.style.fontWeight = '600';
        this.toggleBtn.style.cursor = 'pointer';
        this.toggleBtn.style.padding = '0.5rem';

        this.toggleBtn.addEventListener('click', () => {
            if (this.input.type === 'password') {
                this.input.type = 'text';
                this.toggleBtn.textContent = 'Hide';
            } else {
                this.input.type = 'password';
                this.toggleBtn.textContent = 'Show';
            }
        });

        this.input.addEventListener('input', () => {
            onChange(this.input.value);
        });

        this.container.appendChild(this.input);
        this.container.appendChild(this.toggleBtn);
        container.appendChild(this.container);
    }

    getValue(): string {
        return this.input.value;
    }
}
