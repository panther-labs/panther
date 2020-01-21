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

import { Button, Text, Flex, Box, Heading } from 'pouncejs';
import React from 'react';

const ResourceScanningPanel: React.FC = () => {
  const cfnConsoleLink =
    `https://${process.env.AWS_REGION}.console.aws.amazon.com/cloudformation/home?region=${process.env.AWS_REGION}#/stacks/create/review` +
    `?templateURL=https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-compliance-iam/latest/template.yml` +
    `&stackName=panther-compliance-iam-roles` +
    `&param_MasterAccountId=${process.env.AWS_ACCOUNT_ID}`;
  return (
    <Box>
      <Heading size="medium" m="auto" mb={10} color="grey400">
        Add Infrastructure Monitoring
      </Heading>
      <Text size="large" color="grey200" is="p">
        By clicking the button below, you will be redirected to the CloudFormation console to launch
        a stack in your account.
        <br />
        <br />
        This stack will create a ReadOnly IAM Role used to perform baseline and periodic re-scans of
        your AWS Account resources. The role attaches the SecurityAudit policy defined by AWS, and
        additional permissions needed by Panther for gathering more metadata. Please visit our{' '}
        <a
          target="_blank"
          rel="noopener noreferrer"
          href="https://docs.runpanther.io/amazon-web-services/aws-setup/scanning"
        >
          documentation
        </a>{' '}
        to learn more about this functionality.
      </Text>
      <Flex mt={6}>
        <Button
          size="large"
          variant="default"
          is="a"
          target="_blank"
          rel="noopener noreferrer"
          href={cfnConsoleLink}
        >
          Launch Stack
        </Button>
      </Flex>
    </Box>
  );
};

export default ResourceScanningPanel;
