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
import { render, screen } from 'test-utils';
import NavLink from './index';

describe('NavLink', () => {
  const navLinkDisplayName = 'alerts';
  const getNavLink = () =>
    screen.getByText((content, element) => {
      return element.tagName.toLowerCase() === 'a' && element.textContent === navLinkDisplayName;
    });

  it('could render a secondary navigation link', () => {
    const { container } = render(
      <NavLink to="/something/" label={navLinkDisplayName} icon="list" isSecondary />,
      {
        initialRoute: '/something/particular/',
      }
    );

    expect(container).toMatchSnapshot();
  });

  it('matches a URI regardless of hashes or query params', () => {
    render(<NavLink to="/something/" label={navLinkDisplayName} icon="list" />, {
      initialRoute: '/something/#whatever?q=anything',
    });

    expect(getNavLink()).toHaveAttribute('aria-current', 'page');
  });

  it('matches a URI regardless of trailing slashes', () => {
    render(<NavLink to="/whatever" label={navLinkDisplayName} icon="list" />, {
      initialRoute: `/whatever/`,
    });

    expect(getNavLink()).toHaveAttribute('aria-current', 'page');
  });

  it('matches children URIs', () => {
    render(<NavLink to="/something/" label={navLinkDisplayName} icon="list" />, {
      initialRoute: '/something/particular/',
    });

    expect(getNavLink()).toHaveAttribute('aria-current', 'page');
  });

  it('ignores unrelated URIs', () => {
    render(<NavLink to="/something/" label={navLinkDisplayName} icon="list" />, {
      initialRoute: '/something-else/',
    });

    expect(getNavLink()).not.toHaveAttribute('aria-current', 'page');
  });
});
