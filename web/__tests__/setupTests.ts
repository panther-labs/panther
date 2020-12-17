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
import { createSerializer } from 'jest-emotion';
import { configure } from '@testing-library/dom';

// extends the basic `expect` function, by adding additional DOM assertions such as
// `.toHaveAttribute`, `.toHaveTextContent` etc.
// https://github.com/testing-library/jest-dom#table-of-contents
import '@testing-library/jest-dom';

// additional matchers for jest. Adds the ability to instantly check for `null` or to check
// whether a mock has been called before another mock
// https://github.com/jest-community/jest-extended#api
import 'jest-extended';
import {
  ANALYTICS_CONSENT_STORAGE_KEY,
  ERROR_REPORTING_CONSENT_STORAGE_KEY,
} from 'Source/constants';

// In CI where containers have lower CPU/RAM, jest's parallelization may mean that a single
// test might take a lot of seconds to complete (since they all get fractions of resources).
// We set a test timeout of 90 seconds to protect us against false reports in CI, while
// allowing a single test to wait for DOM updates for up to 60 seconds
if (process.env.CI) {
  jest.setTimeout(90000);

  configure({
    asyncUtilTimeout: 60000,
  });
}

// This mocks sentry module for all tests
const MockedSentryScope = { setExtras: jest.fn(), setTag: jest.fn() };
jest.mock('@sentry/browser', () => {
  const original = jest.requireActual('@sentry/browser');
  return {
    ...original,
    init: jest.fn(),
    withScope(callback): any {
      return callback(MockedSentryScope);
    },
    captureException: jest.fn(),
  };
});

// This mocks mixpanel module for all tests
jest.mock('mixpanel-browser', () => {
  const original = jest.requireActual('mixpanel-browser');
  return {
    ...original,
    init: jest.fn(),
    track: jest.fn(),
  };
});

// Mock Ace Editor and map it to a simple <textarea> element so we can easily reason about
// You should use `getByPlaceholderText` in order to get the related textarea field
jest.mock('Components/Editor');

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
 * Make sure that mock style tags exist to help with emotion bugs + mock console.error to "hide"
 * act  warnings
 */

const originalError = global.console.error;
beforeAll(() => {
  // Add a dummy emotion style tag to prevent testing snapshot serializer from failing
  // https://github.com/emotion-js/emotion/issues/1960
  document.head.insertAdjacentHTML(
    'beforeend',
    `<style data-id="jest-emotion-setup" data-emotion="css" />`
  );

  // During testing, we modify `console.error` to "hide" errors that have to do with "act" since they
  // are noisy and force us to write complicated test assertions which the team doesn't agree with
  global.console.error = jest.fn((...args) => {
    if (typeof args[0] === 'string' && args[0].includes('was not wrapped in act')) {
      return undefined;
    }
    return originalError(...args);
  });
});

/**
 * Make sure that localStorage & sessionStorage and mocks are clean before each test
 */
beforeEach(() => {
  // It important clearAllMocks to happen before updating local storage
  jest.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();

  localStorage.setItem(ERROR_REPORTING_CONSENT_STORAGE_KEY, 'true');
  localStorage.setItem(ANALYTICS_CONSENT_STORAGE_KEY, 'true');
});

/**
 * Restore `console.error` to what it originally was
 */
afterAll(() => {
  (global.console.error as jest.Mock).mockRestore();
});

/**
 * Adds a static serializer for emotion classnames to help with snapshot testing
 */
expect.addSnapshotSerializer(
  createSerializer({
    classNameReplacer(className, index) {
      return `panther-${index}`;
    },
  })
);
