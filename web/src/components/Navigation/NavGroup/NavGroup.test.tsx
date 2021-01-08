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
import { render, fireEvent, waitFor } from 'test-utils';
import { Box } from 'pouncejs';
import NavGroup from './index';

const Nav = ({ onSelect }) => {
  const [active, setActive] = React.useState(false);
  const onSelectCallback = () => {
    onSelect();
    setActive(!active);
  };
  return (
    <NavGroup active={active} onSelect={onSelectCallback} label="Test NavGroup" icon="alert">
      <Box>Child 1</Box>
      <Box>Child 2</Box>
    </NavGroup>
  );
};

describe('NavGroup', () => {
  it('could render a collapsing group of items ', async () => {
    const onSelect = jest.fn();
    const { container, getByText, queryByText } = render(<Nav onSelect={onSelect} />);

    expect(container).toMatchSnapshot();
    expect(queryByText('Child 1')).not.toBeInTheDocument();
    expect(queryByText('Child 2')).not.toBeInTheDocument();

    fireEvent.click(getByText('Test NavGroup'));

    await waitFor(() => {
      expect(getByText('Child 1')).toBeInTheDocument();
    });
    expect(getByText('Child 2')).toBeInTheDocument();
    expect(onSelect).toHaveBeenCalled();
  });
});
