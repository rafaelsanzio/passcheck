
import type { Issue } from '../client';

export class IssueList {
    private container: HTMLElement;
    private title: HTMLElement;
    private list: HTMLElement;

    constructor(container: HTMLElement) {
        this.container = document.createElement('div');
        this.container.className = 'issues-container';

        this.title = document.createElement('div');
        this.title.className = 'issues-title';
        this.title.textContent = 'Suggestions';
        this.container.appendChild(this.title);

        this.list = document.createElement('ul');
        this.list.className = 'issues-list';
        this.container.appendChild(this.list);

        container.appendChild(this.container);
    }

    update(issues: Issue[], hibpCount?: number) {
        this.list.innerHTML = '';

        // Add HIBP warning if needed
        if (hibpCount && hibpCount > 0) {
            this.addIssue({
                code: 'HIBP_BREACHED',
                message: `Breached! Found ${hibpCount.toLocaleString()} times in data leaks.`,
                category: 'breach',
                severity: 3
            });
        }

        if (issues && issues.length > 0) {
            issues.forEach(issue => this.addIssue(issue));
        }

        if (this.list.children.length > 0) {
            this.container.classList.add('visible');
        } else {
            this.container.classList.remove('visible');
        }
    }

    private addIssue(issue: Issue) {
        const item = document.createElement('li');
        item.className = 'issue-item';

        // Warning icon
        item.innerHTML = `
            <span class="issue-icon">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                </svg>
            </span>
            <span>${issue.message}</span>
        `;
        this.list.appendChild(item);
    }

    reset() {
        this.list.innerHTML = '';
        this.container.classList.remove('visible');
    }
}
