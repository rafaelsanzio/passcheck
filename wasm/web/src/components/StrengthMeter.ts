
export class StrengthMeter {
    private bar: HTMLElement;
    private verdict: HTMLElement;
    private entropy: HTMLElement;
    private container: HTMLElement; // Added this line based on the provided code, as `this.container` is used in the constructor.

    constructor(container: HTMLElement) {
        const wrapper = document.createElement('div');

        this.container = document.createElement('div');
        this.container.className = 'strength-meter-container';

        this.bar = document.createElement('div');
        this.bar.className = 'strength-bar';
        this.container.appendChild(this.bar);

        this.verdict = document.createElement('div');
        this.verdict.className = 'verdict-text';

        this.entropy = document.createElement('div');
        this.entropy.className = 'entropy-display';

        wrapper.appendChild(this.container);
        wrapper.appendChild(this.verdict);
        wrapper.appendChild(this.entropy);
        container.appendChild(wrapper);
    }

    update(score: number, verdictText: string, entropyBits: number) {
        this.bar.style.width = `${score}%`;

        // Color based on score
        let color = '#ef4444'; // Red
        if (score >= 20) color = '#f97316'; // Orange
        if (score >= 40) color = '#eab308'; // Yellow
        if (score >= 60) color = '#84cc16'; // Lime
        if (score >= 80) color = '#22c55e'; // Green

        this.bar.style.backgroundColor = color;
        this.verdict.textContent = verdictText;
        this.verdict.style.color = color;

        this.entropy.textContent = `${Math.round(entropyBits)} bits of entropy`;
    }

    reset() {
        this.bar.style.width = '0';
        this.verdict.textContent = '';
        this.entropy.textContent = '';
    }
}
