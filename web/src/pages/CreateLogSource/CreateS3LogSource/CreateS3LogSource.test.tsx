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
  waitMs,
  buildListAvailableLogTypesResponse,
  buildAddS3LogIntegrationInput,
  fireClickAndMouseEvents,
  buildS3PrefixLogTypesInput,
  buildIntegrationTemplate,
  waitForElementToBeRemoved,
  buildS3LogIntegrationHealth,
  buildIntegrationItemHealthStatus,
} from 'test-utils';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { LOG_ONBOARDING_SNS_DOC_URL } from 'Source/constants';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { mockGetLogCfnTemplate } from 'Components/wizards/S3LogSourceWizard';
import { pantherConfig } from 'Source/config';
import { mockGetS3LogSource } from 'Pages/EditS3LogSource/graphql/getS3LogSource.generated';
import { mockAddS3LogSource } from './graphql/addS3LogSource.generated';
import CreateS3LogSource from './CreateS3LogSource';

jest.mock('Helpers/analytics');

const healthyS3 = buildS3LogIntegration({
  health: buildS3LogIntegrationHealth({
    kmsKeyStatus: buildIntegrationItemHealthStatus({ healthy: true }),
    processingRoleStatus: buildIntegrationItemHealthStatus({ healthy: true }),
    s3BucketStatus: buildIntegrationItemHealthStatus({ healthy: true }),
    getObjectStatus: buildIntegrationItemHealthStatus({ healthy: true }),
    bucketNotificationsStatus: buildIntegrationItemHealthStatus({ healthy: true }),
  }),
});
describe('CreateS3LogSource', () => {
  it('can successfully onboard an S3 log source without managed notifications', async () => {
    const logTypesResponse = buildListAvailableLogTypesResponse({
      logTypes: ['AWS.ALB', 'AWS.S3'],
    });
    const logSource = buildS3LogIntegration({
      awsAccountId: '123123123123',
      s3PrefixLogTypes: [buildS3PrefixLogTypesInput({ logTypes: logTypesResponse.logTypes })],
      kmsKey: '',
      managedBucketNotifications: false,
    });

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: logTypesResponse,
        },
      }),
      mockGetLogCfnTemplate({
        variables: {
          input: {
            awsAccountId: pantherConfig.AWS_ACCOUNT_ID,
            integrationLabel: logSource.integrationLabel,
            s3Bucket: logSource.s3Bucket,
            kmsKey: logSource.kmsKey || null,
            managedBucketNotifications: false,
          },
        },
        data: {
          getS3LogIntegrationTemplate: buildIntegrationTemplate(),
        },
      }),
      mockAddS3LogSource({
        variables: {
          input: buildAddS3LogIntegrationInput({
            integrationLabel: logSource.integrationLabel,
            awsAccountId: logSource.awsAccountId,
            s3Bucket: logSource.s3Bucket,
            s3PrefixLogTypes: logSource.s3PrefixLogTypes,
            kmsKey: logSource.kmsKey,
            managedBucketNotifications: logSource.managedBucketNotifications,
          }),
        },
        data: {
          addS3LogIntegration: buildS3LogIntegration({
            integrationId: healthyS3.integrationId,
            managedBucketNotifications: false,
          }),
        },
      }),
      mockGetS3LogSource({
        variables: { id: healthyS3.integrationId },
        data: {
          getS3LogIntegration: healthyS3,
        },
      }),
    ];
    const {
      getByText,
      getByLabelText,
      getByAltText,
      findByText,
      getAllByLabelText,
      queryByText,
      getByAriaLabel,
    } = render(<CreateS3LogSource />, {
      mocks,
    });

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: logSource.integrationLabel } });
    fireEvent.change(getByLabelText('AWS Account ID'), {target: {value: logSource.awsAccountId } }); // prettier-ignore
    fireEvent.change(getByLabelText('Bucket Name'), { target: { value: logSource.s3Bucket } });
    fireEvent.change(getByLabelText('S3 Prefix Filter (leave empty to allow all)'), {target: {value: logSource.s3PrefixLogTypes[0].prefix } }); // prettier-ignore
    // Adding 2 logTypes for this prefix
    fireEvent.change(getAllByLabelText('Log Types')[0], {target: {value: logSource.s3PrefixLogTypes[0].logTypes[0] } }); // prettier-ignore
    fireClickAndMouseEvents(await findByText(logSource.s3PrefixLogTypes[0].logTypes[0]));
    fireEvent.change(getAllByLabelText('Log Types')[0], {target: {value: logSource.s3PrefixLogTypes[0].logTypes[1] } }); // prettier-ignore
    fireClickAndMouseEvents(await findByText(logSource.s3PrefixLogTypes[0].logTypes[1]));
    // Wait for form validation to kick in and move on to the next screen
    await waitMs(50);
    fireEvent.click(getByText('Continue'));

    // Expect to see two buttons for user to select if wants to let us managed notifications
    expect(getByText('Yes, manage my notifications')).toBeInTheDocument();
    expect(getByText("No, don't manage my notifications")).toBeInTheDocument();
    // And user selects to do them manually
    fireEvent.click(getByText("No, don't manage my notifications"));
    // Initially we expect a disabled button while the template is being fetched ...
    expect(getByText('Get template file')).toHaveAttribute('disabled');
    expect(getByText('Launch Console')).toHaveAttribute('aria-disabled', 'true');

    // ... replaced by an active button as soon as it's fetched
    await waitFor(() => expect(getByText('Get template file')).not.toHaveAttribute('disabled'));
    expect(getByText('Launch Console')).toHaveAttribute('aria-disabled', 'false');
    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();
    // ... followed by a "setup notifications" screen
    expect(await findByText('Adding Notifications for New Data')).toBeInTheDocument();
    expect(getByText('steps found here')).toHaveAttribute('href', LOG_ONBOARDING_SNS_DOC_URL);

    // expect NOT to see an error for failed managed notification since user selected to do it manually
    expect(queryByText('Setting up managed notifications failed'));
    // ... replaced by a success screen
    fireEvent.click(getByText('I Have Setup Notifications'));
    const loadingInterfaceElement = getByAriaLabel('Loading...');
    expect(loadingInterfaceElement).toBeInTheDocument();

    // Wait for it to not exist anymore
    await waitForElementToBeRemoved(loadingInterfaceElement);
    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    expect(getByText('Add Another')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedLogSource,
      src: SrcEnum.LogSources,
      ctx: 'S3',
    });
  });

  it('can successfully onboard an S3 log source with successful managed notifications', async () => {
    const logTypesResponse = buildListAvailableLogTypesResponse({
      logTypes: ['AWS.ALB', 'AWS.S3'],
    });
    const logSource = buildS3LogIntegration({
      awsAccountId: '123123123123',
      s3PrefixLogTypes: [buildS3PrefixLogTypesInput({ logTypes: logTypesResponse.logTypes })],
      kmsKey: '',
    });

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: logTypesResponse,
        },
      }),
      mockGetLogCfnTemplate({
        variables: {
          input: {
            awsAccountId: pantherConfig.AWS_ACCOUNT_ID,
            integrationLabel: logSource.integrationLabel,
            s3Bucket: logSource.s3Bucket,
            kmsKey: logSource.kmsKey || null,
            managedBucketNotifications: true,
          },
        },
        data: {
          getS3LogIntegrationTemplate: buildIntegrationTemplate(),
        },
      }),
      mockAddS3LogSource({
        variables: {
          input: buildAddS3LogIntegrationInput({
            integrationLabel: logSource.integrationLabel,
            awsAccountId: logSource.awsAccountId,
            s3Bucket: logSource.s3Bucket,
            s3PrefixLogTypes: logSource.s3PrefixLogTypes,
            kmsKey: logSource.kmsKey,
            managedBucketNotifications: logSource.managedBucketNotifications,
          }),
        },
        data: {
          addS3LogIntegration: buildS3LogIntegration({
            integrationId: healthyS3.integrationId,
            managedBucketNotifications: true,
          }),
        },
      }),
      mockGetS3LogSource({
        variables: { id: healthyS3.integrationId },
        data: {
          getS3LogIntegration: healthyS3,
        },
      }),
    ];
    const {
      getByText,
      getByLabelText,
      getByAltText,
      findByText,
      getAllByLabelText,
      getByAriaLabel,
    } = render(<CreateS3LogSource />, {
      mocks,
    });

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: logSource.integrationLabel } });
    fireEvent.change(getByLabelText('AWS Account ID'), {target: {value: logSource.awsAccountId } }); // prettier-ignore
    fireEvent.change(getByLabelText('Bucket Name'), { target: { value: logSource.s3Bucket } });
    fireEvent.change(getByLabelText('S3 Prefix Filter (leave empty to allow all)'), {target: {value: logSource.s3PrefixLogTypes[0].prefix } }); // prettier-ignore
    // Adding 2 logTypes for this prefix
    fireEvent.change(getAllByLabelText('Log Types')[0], {target: {value: logSource.s3PrefixLogTypes[0].logTypes[0] } }); // prettier-ignore
    fireClickAndMouseEvents(await findByText(logSource.s3PrefixLogTypes[0].logTypes[0]));
    fireEvent.change(getAllByLabelText('Log Types')[0], {target: {value: logSource.s3PrefixLogTypes[0].logTypes[1] } }); // prettier-ignore
    fireClickAndMouseEvents(await findByText(logSource.s3PrefixLogTypes[0].logTypes[1]));
    // Wait for form validation to kick in and move on to the next screen
    await waitMs(1);
    fireEvent.click(getByText('Continue'));

    // Expect to see two buttons for user to select if wants to let us managed notifications
    expect(getByText('Yes, manage my notifications')).toBeInTheDocument();
    expect(getByText("No, don't manage my notifications")).toBeInTheDocument();
    // And user selects to let Panther try to manage them
    fireEvent.click(getByText('Yes, manage my notifications'));
    // Initially we expect a disabled button while the template is being fetched ...
    expect(getByText('Get template file')).toHaveAttribute('disabled');

    // ... replaced by an active button as soon as it's fetched
    await waitFor(() => expect(getByText('Get template file')).not.toHaveAttribute('disabled'));

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    const validatingSourceHealthLoading = getByAltText('Validating source health...');
    expect(validatingSourceHealthLoading).toBeInTheDocument();
    await waitForElementToBeRemoved(validatingSourceHealthLoading);
    const loadingInterfaceElement = getByAriaLabel('Loading...');
    expect(loadingInterfaceElement).toBeInTheDocument();

    // Wait for it to not exist anymore
    await waitForElementToBeRemoved(loadingInterfaceElement);
    // Expect to see the success screen directly since notifications have been successfully managed by us
    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    expect(getByText('Add Another')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedLogSource,
      src: SrcEnum.LogSources,
      ctx: 'S3',
    });
  });

  it('can successfully onboard an S3 log source with failed managed notifications', async () => {
    const logTypesResponse = buildListAvailableLogTypesResponse({
      logTypes: ['AWS.ALB', 'AWS.S3'],
    });
    const logSource = buildS3LogIntegration({
      awsAccountId: '123123123123',
      s3PrefixLogTypes: [buildS3PrefixLogTypesInput({ logTypes: logTypesResponse.logTypes })],
      kmsKey: '',
      notificationsConfigurationSucceeded: false,
    });

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: logTypesResponse,
        },
      }),
      mockGetLogCfnTemplate({
        variables: {
          input: {
            awsAccountId: pantherConfig.AWS_ACCOUNT_ID,
            integrationLabel: logSource.integrationLabel,
            s3Bucket: logSource.s3Bucket,
            kmsKey: logSource.kmsKey || null,
            managedBucketNotifications: true,
          },
        },
        data: {
          getS3LogIntegrationTemplate: buildIntegrationTemplate(),
        },
      }),
      mockAddS3LogSource({
        variables: {
          input: buildAddS3LogIntegrationInput({
            integrationLabel: logSource.integrationLabel,
            awsAccountId: logSource.awsAccountId,
            s3Bucket: logSource.s3Bucket,
            s3PrefixLogTypes: logSource.s3PrefixLogTypes,
            kmsKey: logSource.kmsKey,
            managedBucketNotifications: logSource.managedBucketNotifications,
          }),
        },
        data: {
          addS3LogIntegration: logSource,
        },
      }),
      mockGetS3LogSource({
        variables: { id: logSource.integrationId },
        data: {
          getS3LogIntegration: healthyS3,
        },
      }),
    ];
    const {
      getByText,
      getByLabelText,
      getByAltText,
      findByText,
      getAllByLabelText,
      getByAriaLabel,
    } = render(<CreateS3LogSource />, {
      mocks,
    });

    // Fill in  the form and press continue
    fireEvent.change(getByLabelText('Name'), { target: { value: logSource.integrationLabel } });
    fireEvent.change(getByLabelText('AWS Account ID'), {target: {value: logSource.awsAccountId } }); // prettier-ignore
    fireEvent.change(getByLabelText('Bucket Name'), { target: { value: logSource.s3Bucket } });
    fireEvent.change(getByLabelText('S3 Prefix Filter (leave empty to allow all)'), {target: {value: logSource.s3PrefixLogTypes[0].prefix } }); // prettier-ignore
    // Adding 2 logTypes for this prefix
    fireEvent.change(getAllByLabelText('Log Types')[0], {target: {value: logSource.s3PrefixLogTypes[0].logTypes[0] } }); // prettier-ignore
    fireClickAndMouseEvents(await findByText(logSource.s3PrefixLogTypes[0].logTypes[0]));
    fireEvent.change(getAllByLabelText('Log Types')[0], {target: {value: logSource.s3PrefixLogTypes[0].logTypes[1] } }); // prettier-ignore
    fireClickAndMouseEvents(await findByText(logSource.s3PrefixLogTypes[0].logTypes[1]));
    // Wait for form validation to kick in and move on to the next screen
    await waitMs(50);
    fireEvent.click(getByText('Continue'));

    // Expect to see two buttons for user to select if wants to let us managed notifications
    expect(getByText('Yes, manage my notifications')).toBeInTheDocument();
    expect(getByText("No, don't manage my notifications")).toBeInTheDocument();
    // And user selects to let Panther try to manage them
    fireEvent.click(getByText('Yes, manage my notifications'));
    // Initially we expect a disabled button while the template is being fetched ...
    expect(getByText('Get template file')).toHaveAttribute('disabled');
    expect(getByText('Launch Console')).toHaveAttribute('aria-disabled', 'true');

    // ... replaced by an active button as soon as it's fetched
    await waitFor(() => expect(getByText('Get template file')).not.toHaveAttribute('disabled'));
    expect(getByText('Launch Console')).toHaveAttribute('aria-disabled', 'false');

    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();
    // expect to see error of failed to manage notifications
    expect(await findByText('Setting up managed notifications failed'));
    // ... followed by a "setup notifications" screen
    expect(getByText('Adding Notifications for New Data')).toBeInTheDocument();
    expect(getByText('steps found here')).toHaveAttribute('href', LOG_ONBOARDING_SNS_DOC_URL);
    // ... replaced by a success screen
    fireEvent.click(getByText('I Have Setup Notifications'));

    const loadingInterfaceElement = getByAriaLabel('Loading...');
    expect(loadingInterfaceElement).toBeInTheDocument();

    // Wait for it to not exist anymore
    await waitForElementToBeRemoved(loadingInterfaceElement);

    expect(await findByText('Everything looks good!')).toBeInTheDocument();
    expect(getByText('Finish Setup')).toBeInTheDocument();
    expect(getByText('Add Another')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedLogSource,
      src: SrcEnum.LogSources,
      ctx: 'S3',
    });
  });

  it('shows a proper fail message when source validation fails', async () => {
    const errorMessage = "No-can-do's-ville, baby doll";
    const logTypesResponse = buildListAvailableLogTypesResponse();
    const logSource = buildS3LogIntegration({
      awsAccountId: '123123123123',
      s3PrefixLogTypes: [buildS3PrefixLogTypesInput({ logTypes: logTypesResponse.logTypes })],
      kmsKey: '',
    });

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: logTypesResponse,
        },
      }),
      mockAddS3LogSource({
        variables: {
          input: buildAddS3LogIntegrationInput({
            integrationLabel: logSource.integrationLabel,
            awsAccountId: logSource.awsAccountId,
            s3Bucket: logSource.s3Bucket,
            s3PrefixLogTypes: logSource.s3PrefixLogTypes,
            kmsKey: logSource.kmsKey,
            managedBucketNotifications: logSource.managedBucketNotifications,
          }),
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
    fireEvent.change(getByLabelText('Name'), { target: { value: logSource.integrationLabel } });
    fireEvent.change(getByLabelText('AWS Account ID'), { target: {value: logSource.awsAccountId} }); // prettier-ignore
    fireEvent.change(getByLabelText('Bucket Name'), { target: { value: logSource.s3Bucket } });
    fireEvent.change(getByLabelText('S3 Prefix Filter (leave empty to allow all)'), {target: {value: logSource.s3PrefixLogTypes[0].prefix } }); // prettier-ignore
    fireEvent.change(getAllByLabelText('Log Types')[0], {target: {value: logSource.s3PrefixLogTypes[0].logTypes[0] } }); // prettier-ignore
    fireEvent.click(await findByText(logSource.s3PrefixLogTypes[0].logTypes[0]));

    // Wait for form validation to kick in and move on to the next screen
    await waitMs(1);
    fireEvent.click(getByText('Continue'));

    // User selects to let Panther try to manage notifications
    fireEvent.click(getByText('Yes, manage my notifications'));
    // We move on to the final screen
    fireEvent.click(getByText('Continue'));

    // Expect to see a loading animation while the resource is being validated ...
    expect(getByAltText('Validating source health...')).toBeInTheDocument();

    // ... replaced by a failure screen
    await waitFor(() => {
      expect(getByText("Something didn't go as planned")).toBeInTheDocument();
    });

    expect(getByText('Start over')).toBeInTheDocument();
    expect(getByText(errorMessage)).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackError).toHaveBeenCalledWith({
      event: TrackErrorEnum.FailedToAddLogSource,
      src: SrcEnum.LogSources,
      ctx: 'S3',
    });
  });
});
