
export class SuggestionsList {
    private container: HTMLElement;
    private list: HTMLElement;
    private title: HTMLElement;

    constructor(container: HTMLElement) {
        this.container = document.createElement('div');
        this.container.className = 'suggestions-container';

        this.title = document.createElement('div');
        this.title.className = 'suggestions-title';
        this.title.textContent = 'Strengths';
        this.container.appendChild(this.title);

        this.list = document.createElement('ul');
        this.list.className = 'suggestions-list';
        this.container.appendChild(this.list);

        container.appendChild(this.container);
    }

    update(suggestions: string[]) {
        this.list.innerHTML = '';
        if (!suggestions || suggestions.length === 0) {
            this.container.classList.remove('visible');
            return;
        }

        suggestions.forEach(msg => {
            const item = document.createElement('li');
            item.className = 'suggestion-item';
            item.innerHTML = `
                <span class="suggestion-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                    </svg>
                </span>
                <span>${msg}</span>
            `;
            this.list.appendChild(item);
        });

        this.container.classList.add('visible');
    }

    reset() {
        this.list.innerHTML = '';
        this.container.classList.remove('visible');
    }
}
