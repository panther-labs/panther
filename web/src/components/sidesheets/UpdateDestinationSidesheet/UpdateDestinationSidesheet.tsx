/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import { Alert, Heading, SideSheet, useSnackbar, Box } from 'pouncejs';
import React from 'react';

import pick from 'lodash-es/pick';
import useSidesheet from 'Hooks/useSidesheet';
import { Destination, DestinationConfigInput, DestinationTypeEnum } from 'Generated/schema';

import { BaseDestinationFormValues } from 'Components/forms/BaseDestinationForm';

import SNSDestinationForm from 'Components/forms/SnsDestinationForm';
import SQSDestinationForm from 'Components/forms/SqsDestinationForm';
import SlackDestinationForm from 'Components/forms/SlackDestinationForm';
import PagerDutyDestinationForm from 'Components/forms/PagerdutyDestinationForm';
import OpsgenieDestinationForm from 'Components/forms/OpsgenieDestinationForm';
import MicrosoftTeamsDestinationForm from 'Components/forms/MicrosoftTeamsDestinationForm';
import JiraDestinationForm from 'Components/forms/JiraDestinationForm';
import GithubDestinationForm from 'Components/forms/GithubDestinationForm';
import AsanaDestinationForm from 'Components/forms/AsanaDestinationForm';

import { extractErrorMessage } from 'Helpers/utils';
import { useUpdateDestination } from './graphql/updateDestination.generated';

// Normally the `destination` doesn't contain the severities, but because we receive it as a prop
// from the Destinations table, we are able to access a `defaultForSeverities` key that the table
// has assigned for us. Thus the `destination` that we actually received in enhanced with this
// property.
export interface UpdateDestinationSidesheetProps {
  destination: Destination;
}

export const UpdateDestinationSidesheet: React.FC<UpdateDestinationSidesheetProps> = ({
  destination,
}) => {
  const { pushSnackbar } = useSnackbar();
  const { hideSidesheet } = useSidesheet();

  // If destination object exist, handleSubmit should call updateDestination and use attributes from the destination object for form initial values
  const [
    updateDestination,
    { data: updateDestinationData, error: updateDestinationError },
  ] = useUpdateDestination();

  React.useEffect(() => {
    if (updateDestinationData) {
      pushSnackbar({
        variant: 'success',
        title: `Successfully updated ${updateDestinationData.updateDestination.displayName}`,
      });
      hideSidesheet();
    }
  }, [updateDestinationData]);

  const handleSubmit = React.useCallback(
    async (values: BaseDestinationFormValues<Partial<DestinationConfigInput>>) => {
      const { displayName, defaultForSeverity, outputConfig } = values;

      await updateDestination({
        variables: {
          input: {
            // static form values that are present on all Destinations
            displayName,
            defaultForSeverity,

            // needed fields from the server in order to update the selected destination
            outputId: destination.outputId,
            outputType: destination.outputType,

            // dynamic form values that depend on the selected destination
            outputConfig,
          },
        },
      });
    },
    []
  );

  // Normally we would want to perform a single `pick` operation per switch-case and not extend the
  // commonInitialValues that are defined here. Unfortunately, if you do deep picking (i.e. x.w.y)
  // on  lodash's pick, it messes typings and TS fails cause it thinks it doesn't have all the
  // fields it needs. We use `commonInitialValues` to satisfy this exact constraint that was set by
  // the `initialValues` prop of each form.
  const commonInitialValues = pick(destination, ['displayName', 'defaultForSeverity']);

  const renderFullDestinationForm = () => {
    switch (destination.outputType) {
      case DestinationTypeEnum.Pagerduty:
        return (
          <PagerDutyDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, 'pagerDuty.integrationKey'),
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Github:
        return (
          <GithubDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, ['github.repoName', 'github.token']),
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Jira:
        return (
          <JiraDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, [
                'jira.orgDomain',
                'jira.projectKey',
                'jira.userName',
                'jira.apiKey',
                'jira.assigneeId',
                'jira.issueType',
              ]),
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Opsgenie:
        return (
          <OpsgenieDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, 'opsgenie.apiKey'),
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Msteams:
        return (
          <MicrosoftTeamsDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, 'msTeams.webhookURL'),
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Sns:
        return (
          <SNSDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, 'sns.topicArn'),
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Sqs:
        return (
          <SQSDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, 'sqs.queueUrl'),
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Slack:
        return (
          <SlackDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, 'slack.webhookURL'),
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Asana:
        return (
          <AsanaDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: pick(destination.outputConfig, [
                'asana.personalAccessToken',
                'asana.projectGids',
              ]),
            }}
            onSubmit={handleSubmit}
          />
        );
      default:
        return null;
    }
  };

  return (
    <SideSheet open onClose={hideSidesheet}>
      <Box width={465}>
        <Heading size="medium" mb={8}>
          Update {destination.outputType}
        </Heading>
        {updateDestinationError && (
          <Alert
            mt={2}
            mb={6}
            variant="error"
            title="Destination not updated"
            description={
              extractErrorMessage(updateDestinationError) ||
              'An unknown error has occured while trying to update your destination'
            }
          />
        )}
        {renderFullDestinationForm()}
      </Box>
    </SideSheet>
  );
};

export default UpdateDestinationSidesheet;
