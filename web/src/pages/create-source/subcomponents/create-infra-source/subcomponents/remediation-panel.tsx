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

import React from 'react';
import { Box, Button, Heading, Text } from 'pouncejs';

const RemediationPanel: React.FC = () => {
  const cfnConsoleLink =
    `https://${process.env.AWS_REGION}.console.aws.amazon.com/cloudformation/home?region=${process.env.AWS_REGION}#/stacks/create/review` +
    `?templateURL=https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-remediations-iam/latest/template.yml` +
    `&stackName=panther-remediations-iam-roles` +
    `&param_MasterAccountId=${process.env.AWS_ACCOUNT_ID}`;

  return (
    <Box>
      <Heading size="medium" m="auto" mb={10} color="grey400">
        Setup AWS Automatic Remediation (Optional)
      </Heading>
      <Text size="large" color="grey200" mb={10} is="p">
        By clicking the button below, you will be redirected to the CloudFormation console to launch
        a stack in your account.
        <br />
        <br />
        This stack will configure Panther to fix misconfigured infrastructure as soon as it is
        detected. Remediations can be configured on a per-policy basis to take any desired actions.
        <br />
        <br />
        If you need more information on the process, please visit our{' '}
        <a
          target="_blank"
          rel="noopener noreferrer"
          href="https://docs.runpanther.io/amazon-web-services/aws-setup/automatic-remediation"
        >
          documentation
        </a>{' '}
        to learn more about this functionality.
      </Text>
      <Button
        size="large"
        variant="default"
        target="_blank"
        is="a"
        rel="noopener noreferrer"
        href={cfnConsoleLink}
      >
        Launch Stack
      </Button>
    </Box>
  );
};

export default RemediationPanel;
