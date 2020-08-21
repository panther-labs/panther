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
import NavLink from './index';

describe('NavLink', () => {
  it('matches a URI regardless of hashes or query params', () => {
    const { getByText } = render(<NavLink to="/something/" label="alerts" icon="list" />, {
      initialRoute: '/something/#whatever?q=anything',
    });

    expect(getByText('alerts').closest('a')).toHaveAttribute('aria-current', 'page');
  });

  it('matches a URI regardless of trailing slashes', () => {
    const { getByText } = render(<NavLink to="/whatever" label="alerts" icon="list" />, {
      initialRoute: `/whatever/`,
    });

    expect(getByText('alerts').closest('a')).toHaveAttribute('aria-current', 'page');
  });

  it('matches children URIs', () => {
    const { getByText } = render(<NavLink to="/something/" label="alerts" icon="list" />, {
      initialRoute: '/something/particular/',
    });

    expect(getByText('alerts').closest('a')).toHaveAttribute('aria-current', 'page');
  });

  it('ignores unrelated URIs', () => {
    const { getByText } = render(<NavLink to="/something/" label="alerts" icon="list" />, {
      initialRoute: '/something-else/',
    });

    expect(getByText('alerts').closest('a')).not.toHaveAttribute('aria-current', 'page');
  });
});
