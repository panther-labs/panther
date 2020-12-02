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

import { render, buildS3LogIntegration } from 'test-utils';
import React from 'react';
import { formatDatetime } from 'Helpers/utils';
import flatten from 'lodash/flatten';
import { S3LogSourceCard } from './index';

describe('S3LogSourceCard', () => {
  it('displays the needed data for S3', async () => {
    const source = buildS3LogIntegration();
    const { getByText, getByAriaLabel, getByAltText } = render(<S3LogSourceCard source={source} />);

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    expect(getByAriaLabel(/Toggle Options/i)).toBeInTheDocument();
    expect(getByText(source.integrationLabel)).toBeInTheDocument();
    expect(getByText(source.s3Prefix)).toBeInTheDocument();
    expect(getByText(source.s3Bucket)).toBeInTheDocument();
    expect(getByText(source.kmsKey)).toBeInTheDocument();
    expect(getByText(formatDatetime(source.createdAtTime, true))).toBeInTheDocument();
    flatten(source.s3PrefixLogTypes.map(({ logTypes }) => logTypes)).forEach(logType => {
      expect(getByText(logType)).toBeInTheDocument();
    });
  });
});
