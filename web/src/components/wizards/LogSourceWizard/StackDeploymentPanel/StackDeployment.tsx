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

import { Text, Box, Heading, Spinner, Flex, Link } from 'pouncejs';
import React from 'react';
import { extractErrorMessage, toStackNameFormat } from 'Helpers/utils';
import { useFormikContext } from 'formik';
import { LOG_ONBOARDING_DOC_URL } from 'Source/constants';
import { useGetLogCfnTemplate } from './graphql/getLogCfnTemplate.generated';
import { LogSourceWizardValues } from '../LogSourceWizard';

const StackDeployment: React.FC = () => {
  const { initialValues, values, setStatus } = useFormikContext<LogSourceWizardValues>();
  const { data, loading, error } = useGetLogCfnTemplate({
    variables: {
      input: {
        awsAccountId: process.env.AWS_ACCOUNT_ID,
        integrationLabel: values.integrationLabel,
        s3Bucket: values.s3Bucket,
        logTypes: values.logTypes,
        s3Prefix: values.s3Prefix || null,
        kmsKey: values.kmsKey || null,
      },
    },
  });

  const downloadRef = React.useCallback(
    node => {
      if (data && node) {
        const blob = new Blob([data.getLogIntegrationTemplate.body], {
          type: 'text/yaml;charset=utf-8',
        });

        const downloadUrl = URL.createObjectURL(blob);
        node.setAttribute('href', downloadUrl);
      }
    },
    [data]
  );

  const renderContent = () => {
    if (loading) {
      return <Spinner size="small" />;
    }

    if (error) {
      return (
        <Text size="large" color="red300">
          Couldn{"'"}t generate a Cloudformation template. {extractErrorMessage(error)}
        </Text>
      );
    }

    const { stackName } = data.getLogIntegrationTemplate;
    if (!initialValues.integrationId) {
      const cfnConsoleLink =
        `https://${process.env.AWS_REGION}.console.aws.amazon.com/cloudformation/home?region=${process.env.AWS_REGION}#/stacks/create/review` +
        '?templateURL=https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-log-analysis-iam/v1.0.0/template.yml' +
        `&stackName=${stackName}` +
        `&param_MasterAccountId=${process.env.AWS_ACCOUNT_ID}` +
        `&param_RoleSuffix=${toStackNameFormat(values.integrationLabel)}` +
        `&param_S3Bucket=${values.s3Bucket}` +
        `&param_S3Prefix=${values.s3Prefix}` +
        `&param_KmsKey=${values.kmsKey}`;

      return (
        <React.Fragment>
          <Heading size="medium" m="auto" mb={2} color="grey400">
            Step 1: Allow Panther to Read S3 Data
          </Heading>
          <Text size="large" color="grey200" as="p" mb={10}>
            To proceed, you must deploy the generated Cloudformation template to the AWS account{' '}
            <b>{values.awsAccountId}</b>.{' '}
            {!initialValues.integrationId
              ? 'This will create a ReadOnly IAM Role to access the logs.'
              : 'This will update the existing ReadOnly IAM Role.'}
          </Text>
          <Text size="large" color="grey200" as="p" mt={2} mb={2}>
            The quickest way to do it is through the AWS console
          </Text>
          <Link
            external
            color="blue300"
            title="Launch Cloudformation console"
            href={cfnConsoleLink}
            onClick={() => setStatus({ cfnTemplateDownloaded: true })}
          >
            Launch stack
          </Link>
          <Text size="large" color="grey200" as="p" mt={10} mb={2}>
            Alternatively, you can download it and deploy it through the AWS CLI with the stack name{' '}
            <b>{stackName}</b>
          </Text>
          <Link
            color="blue300"
            href="#"
            title="Download Cloudformation template"
            download={`${stackName}.yml`}
            ref={downloadRef}
            onClick={() => setStatus({ cfnTemplateDownloaded: true })}
          >
            Download template
          </Link>
          <Heading size="medium" m="auto" mt={8} color="grey400">
            Step 2: Adding Notifications For New Data
          </Heading>
          <Text size="large" color="grey200" as="p" mt={4} mb={2}>
            After deploying the stack above, follow the steps{' '}
            <Link
              external
              color="blue300"
              title="SNS Notification Setup"
              href={LOG_ONBOARDING_DOC_URL}
            >
              here
            </Link>{' '}
            to notify Panther when new data becomes available for analysis.
          </Text>
        </React.Fragment>
      );
    }

    return (
      <React.Fragment>
        <Heading size="medium" m="auto" mb={2} color="grey400">
          Deploy your configured stack
        </Heading>
        <Text size="large" color="grey200" as="p" mb={10}>
          To proceed, you must deploy the generated Cloudformation template to the AWS account{' '}
          <b>{values.awsAccountId}</b>.{' '}
          {!initialValues.integrationId
            ? 'This will create a ReadOnly IAM Role to access the logs.'
            : 'This will update the existing ReadOnly IAM Role.'}
        </Text>
        <Box as="ol">
          <Flex as="li" align="center" mb={3}>
            <Text size="large" color="grey200" mr={1}>
              1.
            </Text>
            <Link
              color="blue300"
              href="#"
              title="Download Cloudformation template"
              download={`${initialValues.initialStackName}.yml`}
              ref={downloadRef}
              onClick={() => setStatus({ cfnTemplateDownloaded: true })}
            >
              Download template
            </Link>
          </Flex>
          <Text size="large" as="li" color="grey200" mb={3}>
            2. Log into your
            <Link
              external
              ml={1}
              color="blue300"
              title="Launch Cloudformation console"
              href={`https://${process.env.AWS_REGION}.console.aws.amazon.com/cloudformation/home`}
            >
              Cloudformation console
            </Link>{' '}
            of the account <b>{values.awsAccountId}</b>
          </Text>
          <Text size="large" as="li" color="grey200" mb={3}>
            3. Find the stack <b>{initialValues.initialStackName}</b>
          </Text>
          <Text size="large" as="li" color="grey200" mb={3}>
            4. Press <b>Update</b>, choose <b>Replace current template</b>
          </Text>
          <Text size="large" as="li" color="grey200" mb={3}>
            5. Press <b>Next</b> and finally click on <b>Update</b>
          </Text>
        </Box>
        <Text size="large" color="grey200" as="p" mt={10} mb={2}>
          Alternatively, you can update your stack through the AWS CLI
        </Text>
      </React.Fragment>
    );
  };

  return <Box>{renderContent()}</Box>;
};

export default StackDeployment;
