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
import { Box, Button, Flex, Heading, Text } from 'pouncejs';
import { useFormikContext } from 'formik';
import { CreateLogSourceValues } from '../index';

const CfnLaunchPanel: React.FC = () => {
  const {
    values: { s3Buckets, kmsKeys },
  } = useFormikContext<CreateLogSourceValues>();

  const safeS3Arns = s3Buckets.map(bucket => `arn:aws:s3:::${encodeURIComponent(bucket)}`);
  const safeKmsKeys = kmsKeys.map(key => encodeURIComponent(key));

  const cfnConsoleLink =
    `https://${process.env.AWS_REGION}.console.aws.amazon.com/cloudformation/home?region=${process.env.AWS_REGION}#/stacks/create/review` +
    '?templateURL=https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-log-processing-iam/latest/template.yml' +
    '&stackName=panther-log-processing-iam-roles' +
    `&param_MasterAccountId=${process.env.AWS_ACCOUNT_ID}` +
    `&param_S3Buckets=${safeS3Arns.join(',')}` +
    `&param_EncryptionKeys=${safeKmsKeys.join(',')}` +
    `&param_S3ObjectPrefixes=${safeS3Arns
      .map(s3Arn => `${s3Arn}${encodeURIComponent('/*')}`)
      .join(',')}`;

  return (
    <Box>
      <Heading size="medium" m="auto" mb={10} color="grey400">
        Grant us permission to read
      </Heading>
      <Text size="large" color="grey200" is="p">
        By clicking the button below, you will be redirected to the CloudFormation console to launch
        a stack in your account.
        <br />
        <br />
        This stack will create a ReadOnly IAM Role used to read gathered logs that are accumulated
        into the S3 buckets that you specified.
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

export default CfnLaunchPanel;
