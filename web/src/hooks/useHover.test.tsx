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
