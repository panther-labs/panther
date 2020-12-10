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
import {
  render,
  fireEvent,
  buildS3LogIntegration,
  waitFor,
  waitMs,
  buildListAvailableLogTypesResponse,
  buildUpdateS3LogIntegrationInput,
  buildS3PrefixLogTypesInput,
  fireClickAndMouseEvents,
  buildIntegrationTemplate,
} from 'test-utils';
import { Route } from 'react-router';
import urls from 'Source/urls';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import { mockGetLogCfnTemplate } from 'Components/wizards/S3LogSourceWizard';
import { pantherConfig } from 'Source/config';
import EditS3LogSource from './EditS3LogSource';
import { mockGetS3LogSource } from './graphql/getS3LogSource.generated';
import { mockUpdateS3LogSource } from './graphql/updateS3LogSource.generated';

jest.mock('Helpers/analytics');

describe('EditS3LogSource', () => {
  it('can successfully update an S3 log source', async () => {
    const logTypesResponse = buildListAvailableLogTypesResponse();
    const logSource = buildS3LogIntegration({
      awsAccountId: '123123123123',
      s3PrefixLogTypes: [buildS3PrefixLogTypesInput({ logTypes: logTypesResponse.logTypes })],
      kmsKey: '',
    });

    const updatedLogSource = buildS3LogIntegration({ ...logSource, integrationLabel: 'new-value' });

    const mocks = [
      mockGetS3LogSource({
        variables: {
          id: logSource.integrationId,
        },
        data: {
          getS3LogIntegration: logSource,
        },
      }),
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: logTypesResponse,
        },
      }),
      mockGetLogCfnTemplate({
        variables: {
          input: {
            awsAccountId: pantherConfig.AWS_ACCOUNT_ID,
            integrationLabel: updatedLogSource.integrationLabel,
            s3Bucket: updatedLogSource.s3Bucket,
            kmsKey: updatedLogSource.kmsKey || null,
          },
        },
        data: {
          getS3LogIntegrationTemplate: buildIntegrationTemplate(),
        },
      }),
      mockUpdateS3LogSource({
        variables: {
          input: buildUpdateS3LogIntegrationInput({
            integrationId: logSource.integrationId,
            integrationLabel: updatedLogSource.integrationLabel,
            s3Bucket: logSource.s3Bucket,
            s3PrefixLogTypes: logSource.s3PrefixLogTypes,
            kmsKey: null,
          }),
        },
        data: {
          updateS3LogIntegration: updatedLogSource,
        },
      }),
    ];
    const { getByText, getByLabelText, getByAltText, findByText } = render(
      <Route path={urls.logAnalysis.sources.edit(':id', ':type')}>
        <EditS3LogSource />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.sources.edit(logSource.integrationId, 's3'),
      }
    );

    const nameField = getByLabelText('Name') as HTMLInputElement;

    //  Wait for GET api request to populate the form
    await waitFor(() => expect(nameField).toHaveValue('Loading...'));
    await waitFor(() => expect(nameField).toHaveValue(logSource.integrationLabel));

    // Fill in  the form and press continue
    fireEvent.change(nameField, { target: { value: updatedLogSource.integrationLabel } });

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(50);
    fireEvent.click(getByText('Continue'));

    // Initially we expect a disabled button while the template is being fetched ...
    expect(getByText('Get template file')).toHaveAttribute('disabled');

    // ... replaced by an active button as soon as it's fetched
    await waitFor(() => expect(getByText('Get template file')).not.toHaveAttribute('disabled'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();

    // ... replaced by a success screen
    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.UpdatedLogSource,
      src: SrcEnum.LogSources,
      ctx: 'S3',
    });
  });

  it('can add a new prefix & update an S3 log source with skipping the template step', async () => {
    const logTypesResponse = buildListAvailableLogTypesResponse({
      logTypes: ['AWS.S3', 'AWS.ALB'],
    });
    const existingPrefixLogType = {
      prefix: '/prefix/existing',
      logTypes: [logTypesResponse.logTypes[0]],
    };
    const logSource = buildS3LogIntegration({
      awsAccountId: '123123123123',
      s3PrefixLogTypes: [existingPrefixLogType],
      kmsKey: '',
    });

    const newS3PrefixLogType = { prefix: '/prefix/new', logTypes: [logTypesResponse.logTypes[1]] };
    const updatedLogSource = buildS3LogIntegration({
      ...logSource,
      s3PrefixLogTypes: [existingPrefixLogType, newS3PrefixLogType],
    });

    const mocks = [
      mockGetS3LogSource({
        variables: {
          id: logSource.integrationId,
        },
        data: {
          getS3LogIntegration: logSource,
        },
      }),
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: logTypesResponse,
        },
      }),
      mockUpdateS3LogSource({
        variables: {
          input: {
            integrationId: updatedLogSource.integrationId,
            integrationLabel: updatedLogSource.integrationLabel,
            s3Bucket: updatedLogSource.s3Bucket,
            s3PrefixLogTypes: updatedLogSource.s3PrefixLogTypes,
            kmsKey: null,
          },
        },
        data: {
          updateS3LogIntegration: updatedLogSource,
        },
      }),
    ];
    const {
      getByText,
      getByLabelText,
      getByAltText,
      findByText,
      getByAriaLabel,
      getAllByLabelText,
      queryByText,
    } = render(
      <Route path={urls.logAnalysis.sources.edit(':id', ':type')}>
        <EditS3LogSource />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.sources.edit(logSource.integrationId, 's3'),
      }
    );

    const nameField = getByLabelText('Name') as HTMLInputElement;

    //  Wait for GET api request to populate the form
    await waitFor(() => expect(nameField).toHaveValue('Loading...'));
    await waitFor(() => expect(nameField).toHaveValue(logSource.integrationLabel));

    // Adding an extra prefix - log type
    await fireClickAndMouseEvents(getByAriaLabel('Add prefix'));
    // Fill in the form for the second prefix - logType item
    fireEvent.change(getAllByLabelText('S3 Prefix Filter')[1], {target: {value: updatedLogSource.s3PrefixLogTypes[1].prefix } }); // prettier-ignore
    fireEvent.change(getAllByLabelText('Log Types')[3], {target: {value: updatedLogSource.s3PrefixLogTypes[1].logTypes[0] } }); // prettier-ignore
    fireClickAndMouseEvents(await findByText(updatedLogSource.s3PrefixLogTypes[1].logTypes[0]));
    // Wait for form validation to kick in and move on to the next screen
    await waitMs(50);
    fireEvent.click(getByText('Continue'));

    // We expect to skip the template step cause user only changed the s3PrefixLogTypes
    expect(queryByText('Get template file')).not.toBeInTheDocument();

    // Expect to see a loading animation while the source is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();

    // ... replaced by a success screen
    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.UpdatedLogSource,
      src: SrcEnum.LogSources,
      ctx: 'S3',
    });
  });

  it('can remove a prefix & update an S3 log source with skipping the template step', async () => {
    const logTypesResponse = buildListAvailableLogTypesResponse({
      logTypes: ['AWS.S3', 'AWS.ALB'],
    });
    const prefixLogType1 = { prefix: '/prefix/1', logTypes: [logTypesResponse.logTypes[1]] };
    const prefixLogType2 = { prefix: '/prefix/2', logTypes: [logTypesResponse.logTypes[1]] };
    const logSource = buildS3LogIntegration({
      awsAccountId: '123123123123',
      s3PrefixLogTypes: [prefixLogType1, prefixLogType2],
      kmsKey: '',
    });

    const updatedLogSource = buildS3LogIntegration({
      ...logSource,
      s3PrefixLogTypes: [prefixLogType2],
    });

    const mocks = [
      mockGetS3LogSource({
        variables: {
          id: logSource.integrationId,
        },
        data: {
          getS3LogIntegration: logSource,
        },
      }),
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: logTypesResponse,
        },
      }),
      mockUpdateS3LogSource({
        variables: {
          input: {
            integrationId: updatedLogSource.integrationId,
            integrationLabel: updatedLogSource.integrationLabel,
            s3Bucket: updatedLogSource.s3Bucket,
            s3PrefixLogTypes: updatedLogSource.s3PrefixLogTypes,
            kmsKey: null,
          },
        },
        data: {
          updateS3LogIntegration: updatedLogSource,
        },
      }),
    ];
    const {
      getByText,
      getByLabelText,
      getByAltText,
      findByText,
      getByAriaLabel,
      queryByText,
    } = render(
      <Route path={urls.logAnalysis.sources.edit(':id', ':type')}>
        <EditS3LogSource />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.sources.edit(logSource.integrationId, 's3'),
      }
    );

    const nameField = getByLabelText('Name') as HTMLInputElement;

    //  Wait for GET api request to populate the form
    await waitFor(() => expect(nameField).toHaveValue('Loading...'));
    await waitFor(() => expect(nameField).toHaveValue(logSource.integrationLabel));

    // Removing the first prefix
    await fireClickAndMouseEvents(getByAriaLabel('Remove prefix 0'));
    // Wait for form validation to kick in and move on to the next screen
    await waitMs(50);
    fireEvent.click(getByText('Continue'));

    // We expect to skip the template step cause user only changed the s3PrefixLogTypes
    expect(queryByText('Get template file')).not.toBeInTheDocument();

    // Expect to see a loading animation while the source is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();

    // ... replaced by a success screen
    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.UpdatedLogSource,
      src: SrcEnum.LogSources,
      ctx: 'S3',
    });
  });
});
