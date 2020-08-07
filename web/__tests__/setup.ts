/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
import path from 'path';
import { loadDotEnvVars, getAppTemplateParams } from '../scripts/utils';

// extends the basic `expect` function, by adding additional DOM assertions such as
// `.toHaveAttribute`, `.toHaveTextContent` etc.
// https://github.com/testing-library/jest-dom#table-of-contents
import '@testing-library/jest-dom';

// additional matchers for jest. Adds the ability to instantly check for `null` or to check
// whether a mock has been called before another mock
// https://github.com/jest-community/jest-extended#api
import 'jest-extended';

window.alert = () => {};
window.scrollTo = () => {};

if (window.matchMedia === undefined) {
  window.matchMedia = () => ({
    media: '',
    matches: false,
    addListener: () => {},
    onchange: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  });
}

// Mock createObjectURL/revokeObjectURL
// https://github.com/jsdom/jsdom/issues/1721#issuecomment-387279017
function noOp() {}

if (window.URL.createObjectURL === undefined) {
  Object.defineProperty(window.URL, 'createObjectURL', { value: noOp });
}
if (window.URL.revokeObjectURL === undefined) {
  Object.defineProperty(window.URL, 'revokeObjectURL', { value: noOp });
}

/**
 * Mock the server-side EJS-injected AWS configuration.
 * See `web/public/index.ejs`
 */
loadDotEnvVars(path.resolve(__dirname, '.env.test'));
const { PANTHER_CONFIG } = getAppTemplateParams();

const scriptTag = document.createElement('script');
scriptTag.id = '__PANTHER_CONFIG__';
scriptTag.type = 'application/json';
scriptTag.innerHTML = JSON.stringify(PANTHER_CONFIG);
document.body.appendChild(scriptTag);

/**
 * During testing, we modify `console.error` to "hide" errors that have to do with "act" since they
 * are noisy and force us to write complicated test assertions which the team doesn't agree with
 */
const originalError = global.console.error;
beforeAll(() => {
  global.console.error = jest.fn((...args) => {
    if (typeof args[0] === 'string' && args[0].includes('was not wrapped in act')) {
      return undefined;
    }
    return originalError(...args);
  });
});

/**
 * Make sure that localStorage & sessionStorage are clean before each test
 */
afterEach(() => {
  localStorage.clear();
  sessionStorage.clear();
});

/**
 * Restore `console.error` to what it originally was
 */
afterAll(() => {
  (global.console.error as jest.Mock).mockRestore();
});
