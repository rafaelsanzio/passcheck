
import './styles/style.css';
import type { PassCheckConfig } from './client';
import { passCheck } from './client';
import { PasswordInput } from './components/PasswordInput';
import { StrengthMeter } from './components/StrengthMeter';
import { RequirementsList } from './components/RequirementsList';
import { IssueList } from './components/IssueList';
import { SuggestionsList } from './components/SuggestionsList';
import { ConfigPanel } from './components/ConfigPanel';

const app = document.querySelector('#app') as HTMLElement;
app.innerHTML = `
  <div class="app-container">
    <h1>PassCheck WASM</h1>
    <div id="config-panel-root"></div>
    <div class="card">
      <div id="password-input-root"></div>
      <div id="strength-meter-root"></div>
      <div id="suggestions-root"></div>
      <div id="requirements-root"></div>
      <div id="issues-root"></div>
    </div>
  </div>
`;

// Default Config
let currentConfig: PassCheckConfig = {
  minLength: 8,
  requireUpper: true,
  requireLower: true,
  requireDigit: true,
  requireSymbol: false,
};

// Initialize Components
const passwordInput = new PasswordInput(document.querySelector('#password-input-root') as HTMLElement, (password) => {
  handleCheck(password);
});

const strengthMeter = new StrengthMeter(document.querySelector('#strength-meter-root') as HTMLElement);
const suggestionsList = new SuggestionsList(document.querySelector('#suggestions-root') as HTMLElement);
const requirementsList = new RequirementsList(document.querySelector('#requirements-root') as HTMLElement, currentConfig);
const issueList = new IssueList(document.querySelector('#issues-root') as HTMLElement);

const _configPanel = new ConfigPanel(document.querySelector('#config-panel-root') as HTMLElement, currentConfig, (newConfig) => {
  currentConfig = newConfig;
  // Update requirements list constraints
  requirementsList.updateConfig(currentConfig);
  // Re-check current password
  handleCheck(passwordInput.getValue());
});

console.log('Config panel initialized', _configPanel);

async function handleCheck(password: string) {
  if (!password) {
    strengthMeter.reset();
    issueList.reset();
    suggestionsList.reset();
    requirementsList.reset();
    return;
  }

  try {
    const res = await passCheck.check(password, currentConfig);

    // Update UI
    strengthMeter.update(res.score, res.verdict, res.entropy);
    requirementsList.update(res.issues, currentConfig);
    suggestionsList.update(res.suggestions);
    issueList.update(res.issues, (res as any).hibpCount);
  } catch (err) {
    console.error(err);
  }
}
