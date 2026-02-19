/**
 * SuggestionsList displays positive feedback about password strengths.
 * Refactored for better organization and cleaner code.
 */
export class SuggestionsList {
    private container: HTMLElement;
    private list: HTMLElement;
    private title: HTMLElement;

    constructor(container: HTMLElement) {
        this.container = this.createContainer();
        this.title = this.createTitle();
        this.list = this.createList();

        this.container.appendChild(this.title);
        this.container.appendChild(this.list);
        container.appendChild(this.container);
    }

    private createContainer(): HTMLElement {
        const container = document.createElement('div');
        container.className = 'suggestions-container';
        return container;
    }

    private createTitle(): HTMLElement {
        const title = document.createElement('div');
        title.className = 'suggestions-title';
        title.textContent = 'Strengths';
        return title;
    }

    private createList(): HTMLElement {
        const list = document.createElement('ul');
        list.className = 'suggestions-list';
        return list;
    }

    /**
     * Updates the suggestions list with new suggestions.
     * Hides the container if no suggestions are provided.
     */
    update(suggestions: string[]): void {
        this.clearList();

        if (!this.hasSuggestions(suggestions)) {
            this.hide();
            return;
        }

        this.renderSuggestions(suggestions);
        this.show();
    }

    /**
     * Resets the component to its initial empty state.
     */
    reset(): void {
        this.clearList();
        this.hide();
    }

    private hasSuggestions(suggestions: string[] | null | undefined): boolean {
        return Array.isArray(suggestions) && suggestions.length > 0;
    }

    private clearList(): void {
        this.list.innerHTML = '';
    }

    private renderSuggestions(suggestions: string[]): void {
        suggestions.forEach(suggestion => {
            const item = this.createSuggestionItem(suggestion);
            this.list.appendChild(item);
        });
    }

    private createSuggestionItem(text: string): HTMLLIElement {
        const item = document.createElement('li');
        item.className = 'suggestion-item';
        item.innerHTML = `
            <span class="suggestion-icon" aria-hidden="true">
                ${this.getCheckIcon()}
            </span>
            <span class="suggestion-text">${this.escapeHtml(text)}</span>
        `;
        return item;
    }

    private getCheckIcon(): string {
        return `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
            </svg>
        `;
    }

    private escapeHtml(text: string): string {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    private show(): void {
        this.container.classList.add('visible');
    }

    private hide(): void {
        this.container.classList.remove('visible');
    }
}
