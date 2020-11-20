/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import useHover from 'Hooks/useHover';
import { render, fireEvent } from 'test-utils';

const TestComponent: React.FC = () => {
  const { isHovering, handlers } = useHover();

  return (
    <div data-testid="test" {...handlers}>
      {String(isHovering)}
    </div>
  );
};

describe('useHover', () => {
  it('correctly handles mouse movement', () => {
    const { getByText, getByTestId } = render(<TestComponent />);

    const element = getByTestId('test');
    expect(getByText('false')).toBeInTheDocument();

    fireEvent.mouseEnter(element);
    expect(getByText('true')).toBeInTheDocument();

    fireEvent.mouseMove(element);
    expect(getByText('true')).toBeInTheDocument();

    fireEvent.mouseLeave(element);
    expect(getByText('false')).toBeInTheDocument();
  });
});
