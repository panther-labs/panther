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
import { GraphQLError } from 'graphql';
import {
  render,
  fireEvent,
  buildS3LogIntegration,
  waitFor,
  buildGetS3LogIntegrationTemplateInput,
  buildIntegrationTemplate,
  waitMs,
} from 'test-utils';
import { mockListAvailableLogTypes } from 'Source/graphql/queries/listAvailableLogTypes.generated';
import { mockGetLogCfnTemplate } from 'Components/wizards/S3LogSourceWizard';
import { mockAddS3LogSource } from './graphql/addS3LogSource.generated';
import CreateS3LogSource from './CreateS3LogSource';

const testName = 'test';
const testAwsAccountID = '123123123123';
const testBucketName = 's3-test-bucket';
const mockPantherAwsAccountId = '456456456456';
const testLogType = 'AWS.S3';

describe('CreateS3LogSource', () => {
  let prevPantherAwsAccountId;
  beforeAll(() => {
    prevPantherAwsAccountId = process.env.AWS_ACCOUNT_ID;
    process.env.PANTHER_VERSION = mockPantherAwsAccountId;
  });

  afterAll(() => {
    process.env.PANTHER_VERSION = prevPantherAwsAccountId;
  });

  it('can successfully onboard an S3 log source', async () => {
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [testLogType],
          },
        },
      }),
      mockGetLogCfnTemplate({
        variables: {
          input: buildGetS3LogIntegrationTemplateInput(),
        },
        data: {
          getS3LogIntegrationTemplate: buildIntegrationTemplate(),
        },
      }),
      mockAddS3LogSource({
        variables: {
          input: {
            integrationLabel: testName,
            awsAccountId: testAwsAccountID,
            s3Bucket: testBucketName,
            logTypes: [testLogType],
            kmsKey: null,
            s3Prefix: null,
          },
        },
        data: {
          addS3LogIntegration: buildS3LogIntegration(),
        },
      }),
    ];
    const { getByText, getByLabelText, getByAltText, findByText, getAllByLabelText } = render(
      <CreateS3LogSource />,
      {
        mocks,
      }
    );

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: testName } });
    fireEvent.change(getByLabelText('AWS Account ID'), { target: { value: testAwsAccountID } });
    fireEvent.change(getByLabelText('Bucket Name'), { target: { value: testBucketName } });
    fireEvent.change(getAllByLabelText('Log Types')[0], { target: { value: testLogType } });
    fireEvent.click(await findByText(testLogType));

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(50);
    fireEvent.click(getByText('Continue Setup'));

    // Initially we expect a disabled button while the template is being fetched ...
    expect(getByText('Get template file')).toHaveAttribute('disabled');

    // ... replaced by an active button as soon as it's fetched
    await waitFor(() => expect(getByText('Get template file')).not.toHaveAttribute('disabled'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();
    expect(getByText('Cancel')).toBeInTheDocument();

    // ... replaced by a success screen
    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    expect(getByText('Add Another')).toBeInTheDocument();
  });

  it('shows a proper fail message when source validation fails', async () => {
    const errorMessage = "No-can-do's-ville, baby doll";
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [testLogType],
          },
        },
      }),
      mockGetLogCfnTemplate({
        variables: {
          input: buildGetS3LogIntegrationTemplateInput(),
        },
        data: {
          getS3LogIntegrationTemplate: buildIntegrationTemplate(),
        },
      }),
      mockAddS3LogSource({
        variables: {
          input: {
            integrationLabel: testName,
            awsAccountId: testAwsAccountID,
            s3Bucket: testBucketName,
            logTypes: [testLogType],
            kmsKey: null,
            s3Prefix: null,
          },
        },
        data: null,
        errors: [new GraphQLError(errorMessage)],
      }),
    ];

    const { getByText, findByText, getByLabelText, getByAltText, getAllByLabelText } = render(
      <CreateS3LogSource />,
      {
        mocks,
      }
    );

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: testName } });
    fireEvent.change(getByLabelText('AWS Account ID'), { target: { value: testAwsAccountID } });
    fireEvent.change(getByLabelText('Bucket Name'), { target: { value: testBucketName } });
    fireEvent.change(getAllByLabelText('Log Types')[0], { target: { value: testLogType } });
    fireEvent.click(await findByText(testLogType));

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(50);
    fireEvent.click(getByText('Continue Setup'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();
    expect(getByText('Cancel')).toBeInTheDocument();

    // ... replaced by a failure screen
    expect(await findByText("Something didn't go as planned")).toBeInTheDocument();
    expect(getByText('Start over')).toBeInTheDocument();
    expect(getByText(errorMessage)).toBeInTheDocument();
  });
});
