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

import SupportPage, { supportLinks } from './Support';

describe('Support page', () => {
  it('should match snapshot', async () => {
    const { container } = render(<SupportPage />);
    expect(container).toMatchSnapshot();
  });
  it('should have proper links', async () => {
    const { getByText } = render(<SupportPage />);
    expect(await getByText('Join Now')).toHaveAttribute('href', supportLinks.slack);
    expect(await getByText('Send your Feedback')).toHaveAttribute(
      'href',
      supportLinks.productBoard
    );
    expect(await getByText(supportLinks.email)).toHaveAttribute(
      'href',
      `mailto:${supportLinks.email}`
    );
    expect(await getByText('Request a demo')).toHaveAttribute('href', supportLinks.demo);
  });
});
