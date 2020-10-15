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
import useForceUpdate from 'Hooks/useForceUpdate';
import { fireEvent, render } from 'test-utils';

const Component = () => {
  const counter = React.useRef(0);
  const forceUpdate = useForceUpdate();

  return (
    <button
      onClick={() => {
        counter.current += 1;
        forceUpdate();
      }}
    >
      rendered {counter.current} times
    </button>
  );
};

describe('useForceUpdate', () => {
  it('forces an update', () => {
    const { getByText } = render(<Component />);

    fireEvent.click(getByText('rendered 0 times'));
    fireEvent.click(getByText('rendered 1 times'));

    expect(getByText('rendered 2 times')).toBeInTheDocument();
  });
});
