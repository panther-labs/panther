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

import { Box, Flex, Button, Img } from 'pouncejs';
import React from 'react';
import { useWizardContext, WizardPanel } from 'Components/Wizard';

import RealTimeNotification from 'Assets/statuses/real-time-notification-green.svg';
import { useFormikContext } from 'formik';
import { S3LogSourceWizardValues } from 'Components/wizards/S3LogSourceWizard/S3LogSourceWizard';

const NotificationsManagementPanel: React.FC = () => {
  const { setFieldValue } = useFormikContext<S3LogSourceWizardValues>();
  const { goToNextStep } = useWizardContext();
  return (
    <WizardPanel>
      <Box width={716} m="auto">
        <WizardPanel.Heading
          title={'Do you want Panther to configure bucket notifications for you?'}
          subtitle={
            "If yes, we will provide you with a CloudFormation template to grant Panther the appropriate permissions. Panther will configure your bucket to send notifications for all s3:CreateObject events to Panther's input data queue. Panther will not overwrite any existing configuration on your bucket."
          }
        />
      </Box>
      <WizardPanel.Actions>
        <Flex width={314} direction="column" align="center" spacing={4}>
          <Img nativeWidth={120} nativeHeight={120} alt="bell" src={RealTimeNotification} />
          <Button
            fullWidth
            onClick={() => {
              setFieldValue('managedBucketNotifications', true);
              goToNextStep();
            }}
          >
            Yes, manage my notifications
          </Button>
          <Button
            fullWidth
            variant="outline"
            variantColor="navyblue"
            onClick={() => {
              setFieldValue('managedBucketNotifications', false);
              goToNextStep();
            }}
          >
            No, don&apos;t manage my notifications
          </Button>
        </Flex>
      </WizardPanel.Actions>
    </WizardPanel>
  );
};

export default NotificationsManagementPanel;
