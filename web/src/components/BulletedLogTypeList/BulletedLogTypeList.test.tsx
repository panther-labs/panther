import React from 'react';
import { render, fireEvent } from 'test-utils';
import BulletedLogTypeList from './BulletedLogTypeList';

describe('BulletedLogTypeList', () => {
  it('matches snapshots', () => {
    const { container, getByText } = render(
      <BulletedLogTypeList logTypes={['a', 'b', 'c', 'd']} limit={4} />
    );
    expect(container).toMatchSnapshot();

    fireEvent.mouseEnter(getByText('+2'));
    expect(container).toMatchSnapshot();
  });
});
