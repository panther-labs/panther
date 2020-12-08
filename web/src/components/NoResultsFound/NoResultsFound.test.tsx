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
import { render } from 'test-utils';
import NoResultsFound from './NoResultsFound';

describe('NoResultsFound', () => {
  it('matches snapshot', () => {
    const { container } = render(<NoResultsFound />);
    expect(container).toMatchSnapshot();
  });

  it('contains proper semantics', () => {
    const { getByText, getByAltText } = render(<NoResultsFound />);
    expect(getByAltText('Document and magnifying glass')).toBeInTheDocument();
    expect(getByText('No Results')).toBeInTheDocument();
  });

  it('allows a user to override the text', () => {
    const { getByText } = render(<NoResultsFound title="Fake title" />);
    expect(getByText('Fake title')).toBeInTheDocument();
  });
});
