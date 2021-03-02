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
import { render, fireEvent } from 'test-utils';
import urls from 'Source/urls';
import Navigation from './Navigation';

describe('Navigation', () => {
  it('renders with active links', () => {
    const { container } = render(<Navigation />, {
      initialRoute: urls.logAnalysis.alerts.list(),
    });

    expect(container).toMatchSnapshot();
  });

  it('renders with all the user infos', () => {
    const { container, userInfo } = render(<Navigation />, {
      initialRoute: urls.logAnalysis.alerts.list(),
    });

    const initials = userInfo.givenName[0] + userInfo.familyName[0];
    const name = `${userInfo.givenName[0]}. ${userInfo.familyName}`;
    expect(container).toHaveTextContent(initials);
    expect(container).toHaveTextContent(name);
  });

  it('renders with all the navigation entries', async () => {
    const { getByText } = render(<Navigation />, {
      initialRoute: urls.logAnalysis.alerts.list(),
    });

    expect(getByText('Alerts')).toBeInTheDocument();
    expect(getByText('Detections')).toBeInTheDocument();

    // Expand
    fireEvent.click(getByText('Log Analysis'));
    expect(getByText('Overview')).toBeInTheDocument();

    // Expand
    fireEvent.click(getByText('Cloud Security'));
    expect(getByText('Resources')).toBeInTheDocument();
    expect(getByText('Settings')).toBeInTheDocument();

    // Expand
    fireEvent.click(getByText('Integrations'));
    expect(getByText('Log Sources')).toBeInTheDocument();
    expect(getByText('Cloud Accounts')).toBeInTheDocument();
    expect(getByText('Alert Destinations')).toBeInTheDocument();

    fireEvent.click(getByText('Settings'));
    expect(getByText('General')).toBeInTheDocument();
    expect(getByText('Global Modules')).toBeInTheDocument();
    expect(getByText('Bulk Uploader')).toBeInTheDocument();

    expect(getByText('Documentation')).toBeInTheDocument();
    expect(getByText('Support')).toBeInTheDocument();
  });
});
