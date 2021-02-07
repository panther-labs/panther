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
import { buildDataModel, render } from 'test-utils';
import DataModelCard from './DataModelCard';

describe('DataModelCard', () => {
  it('matches snapshot', () => {
    const { container } = render(<DataModelCard dataModel={buildDataModel()} />);
    expect(container).toMatchSnapshot();
  });

  it('renders the necessary information', () => {
    const dataModel = buildDataModel();

    const { getByText, getByAriaLabel } = render(<DataModelCard dataModel={dataModel} />);

    expect(getByText(dataModel.id)).toBeInTheDocument();
    expect(getByText(dataModel.displayName)).toBeInTheDocument();
    expect(getByText(dataModel.enabled ? 'ENABLED' : 'DISABLED')).toBeInTheDocument();
    expect(getByAriaLabel('Toggle Options')).toBeInTheDocument();
  });

  it('fallbacks to `id` when display name is not existent', () => {
    const dataModel = buildDataModel({ displayName: '' });

    const { getAllByText } = render(<DataModelCard dataModel={dataModel} />);

    expect(getAllByText(dataModel.id)).toHaveLength(2);
  });
});
