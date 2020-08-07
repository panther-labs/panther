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

import { render } from 'test-utils';
import Breadcrumbs from 'Components/Breadcrumbs/Breadcrumbs';
import urls from 'Source/urls';
import React from 'react';
import { Box, Button } from 'pouncejs';

describe('Breadcrumbs', () => {
  it('renders correct the breadcrumbs', async () => {
    const { container } = render(<Breadcrumbs />, {
      initialRoute: urls.compliance.policies.list(),
    });

    expect(container).toHaveTextContent('Home');
    expect(container.querySelector(`a[href="/"]`)).toBeTruthy();

    expect(container).toHaveTextContent('Policies');
    expect(container.querySelector(`a[href="${urls.compliance.policies.list()}"]`)).toBeTruthy();
  });

  it('places actions as a child of the main header', () => {
    const buttonText = 'Test';

    const header = document.createElement('header');
    header.id = 'main-header';
    document.body.appendChild(header);

    const { getByText } = render(
      <React.Fragment>
        <Breadcrumbs />
        <Box>
          <Box>
            <Breadcrumbs.Actions>
              <Button>{buttonText}</Button>
            </Breadcrumbs.Actions>
          </Box>
        </Box>
      </React.Fragment>,
      { container: header }
    );

    const button = getByText(buttonText);
    expect(button.parentElement).toBe(header);

    // cleanup since it wasn't added by "render"
    header.remove();
  });
});
