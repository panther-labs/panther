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
import { render, buildGeneralSettings, waitFor } from 'test-utils';
import GeneralSettings from './GeneralSettings';
import { mockGetGeneralSettings } from './graphql/getGeneralSettings.generated';

describe('GeneralSettings', () => {
  test('it renders the general settings page along with the footer', async () => {
    const settings = buildGeneralSettings({
      displayName: 'Panther labs',
      email: 'test@runpanther.io',
    });
    const mocks = [mockGetGeneralSettings({ data: { generalSettings: settings } })];

    const { getByText, container, getByLabelText } = render(<GeneralSettings />, {
      mocks,
    });
    await waitFor(() => expect(getByText('Company Information')).toBeInTheDocument());

    expect(getByLabelText('Company Name')).toHaveValue('Panther labs');
    expect(getByLabelText('Email')).toHaveValue('test@runpanther.io');
    expect(getByText('Save')).toBeInTheDocument();

    expect(getByText('Preferences')).toBeInTheDocument();
    expect(getByText('Report Web Application Errors')).toBeInTheDocument();
    expect(getByText('Send Product Analytics')).toBeInTheDocument();

    expect(getByText('Plan')).toBeInTheDocument();
    expect(getByText('AWS Account ID')).toBeInTheDocument();
    expect(getByText('Version')).toBeInTheDocument();
    expect(getByText('AWS Region')).toBeInTheDocument();

    expect(container).toMatchSnapshot();
  });
});
