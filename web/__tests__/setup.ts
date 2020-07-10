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

// Mock the server-side EJS-injected AWS configuration.
// See web/public/index.ejs
const scriptTag = document.createElement('script');
scriptTag.id = '__PANTHER_CONFIG__';
scriptTag.type = 'application/json';
scriptTag.innerHTML = JSON.stringify({
  PANTHER_VERSION: 'test',
  AWS_REGION: 'us-west-2',
  AWS_ACCOUNT_ID: '111111111111',
  WEB_APPLICATION_GRAPHQL_API_ENDPOINT: 'test',
  WEB_APPLICATION_USER_POOL_CLIENT_ID: 'test',
  WEB_APPLICATION_USER_POOL_ID: 'us-west-2_test',
});
document.body.appendChild(scriptTag);
