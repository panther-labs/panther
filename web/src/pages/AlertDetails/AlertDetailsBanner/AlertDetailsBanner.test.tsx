import React from 'react';
import { buildAlertDetails, render } from 'test-utils';
import AlertDetailsBanner from './index';

describe('AlertDetailsBanner', () => {
  it('renders', () => {
    const alert = buildAlertDetails();

    const { container } = render(<AlertDetailsBanner alert={alert} />);
    expect(container).toMatchSnapshot();
  });
});
