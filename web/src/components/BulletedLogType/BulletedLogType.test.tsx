import React from 'react';
import { render } from 'test-utils';
import BulletedLogType from './BulletedLogType';

describe('BulletedLogType', () => {
  it('renders the same color for the same log type', () => {
    const { container } = render(<BulletedLogType logType="AWS.EC2" />);

    expect(container).toMatchSnapshot();
  });
});
