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

import { Text, Box, Spinner, Flex, Link } from 'pouncejs';
import React from 'react';
import { extractErrorMessage, toStackNameFormat } from 'Helpers/utils';
import { useFormikContext } from 'formik';
import { LOG_ONBOARDING_SNS_DOC_URL } from 'Source/constants';
import { WizardPanel } from 'Components/Wizard';
import { pantherConfig } from 'Source/config';
import { useGetLogCfnTemplate } from './graphql/getLogCfnTemplate.generated';
import { S3LogSourceWizardValues } from '../S3LogSourceWizard';

const StackDeployment: React.FC = () => {
  const { initialValues, values, setStatus } = useFormikContext<S3LogSourceWizardValues>();
  const { data, loading, error } = useGetLogCfnTemplate({
    variables: {
      input: {
        awsAccountId: pantherConfig.AWS_ACCOUNT_ID,
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
        const blob = new Blob([data.getS3LogIntegrationTemplate.body], {
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
      return (
        <Flex width={1} justify="center" my={5}>
          <Spinner size="medium" />
        </Flex>
      );
    }

    if (error) {
      return (
        <Text color="red-300">
          Couldn{"'"}t generate a Cloudformation template. {extractErrorMessage(error)}
        </Text>
      );
    }

    const { stackName } = data.getS3LogIntegrationTemplate;
    if (!initialValues.integrationId) {
      const cfnConsoleLink =
        `https://${pantherConfig.AWS_REGION}.console.aws.amazon.com/cloudformation/home?region=${pantherConfig.AWS_REGION}#/stacks/create/review` +
        '?templateURL=https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-log-analysis-iam/v1.0.0/template.yml' +
        `&stackName=${stackName}` +
        `&param_MasterAccountId=${pantherConfig.AWS_ACCOUNT_ID}` +
        `&param_RoleSuffix=${toStackNameFormat(values.integrationLabel)}` +
        `&param_S3Bucket=${values.s3Bucket}` +
        `&param_S3Prefix=${values.s3Prefix}` +
        `&param_KmsKey=${values.kmsKey}`;

      return (
        <React.Fragment>
          <WizardPanel.Heading
            title="Deploy your configured stack"
            subtitle={`To proceed, you must deploy the generated Cloudformation template to the AWS account
          ${values.awsAccountId}.
          ${
            !initialValues.integrationId
              ? 'This will create a ReadOnly IAM Role to access the logs.'
              : 'This will override the existing ReadOnly IAM Role.'
          }`}
          />
          <Box fontSize="medium" mb={10}>
            <Text color="gray-300" mt={2} mb={2}>
              The quickest way to do it is through the AWS console
            </Text>
            <Link
              external
              title="Launch Cloudformation console"
              href={cfnConsoleLink}
              onClick={() => setStatus({ cfnTemplateDownloaded: true })}
            >
              Launch stack
            </Link>
            <Text color="gray-300" mt={10} mb={2}>
              Alternatively, you can download it and deploy it through the AWS CLI with the stack
              name <b>{stackName}</b>
            </Text>
            <Link
              href="#"
              title="Download Cloudformation template"
              download={`${stackName}.yml`}
              ref={downloadRef}
              onClick={() => setStatus({ cfnTemplateDownloaded: true })}
            >
              Download template
            </Link>
          </Box>
          <WizardPanel.Heading
            title="Step 2: Adding Notifications For New Data"
            subtitle={[
              'After deploying the stack above, follow the steps ',
              <Link
                key={0}
                external
                title="SNS Notification Setup"
                href={LOG_ONBOARDING_SNS_DOC_URL}
              >
                here
              </Link>,
              ' to notify Panther when new data becomes available for analysis.',
            ]}
          />
        </React.Fragment>
      );
    }

    return (
      <React.Fragment>
        <WizardPanel.Heading
          title="Deploy your configured stack"
          subtitle={`To proceed, you must deploy the generated Cloudformation template to the AWS account
          ${values.awsAccountId}.
          ${
            !initialValues.integrationId
              ? 'This will create a ReadOnly IAM Role to access the logs.'
              : 'This will override the existing ReadOnly IAM Role.'
          }`}
        />
        <Box as="ol" fontSize="medium">
          <Flex as="li" align="center" mb={3}>
            <Box color="gray-300" mr={1}>
              1.
            </Box>
            <Link
              href="#"
              title="Download Cloudformation template"
              download={`${initialValues.initialStackName}.yml`}
              ref={downloadRef}
              onClick={() => setStatus({ cfnTemplateDownloaded: true })}
            >
              Download template
            </Link>
          </Flex>
          <Box as="li" color="gray-300" mb={3}>
            2. Log into your
            <Link
              external
              ml={1}
              title="Launch Cloudformation console"
              href={`https://${pantherConfig.AWS_REGION}.console.aws.amazon.com/cloudformation/home`}
            >
              Cloudformation console
            </Link>{' '}
            of the account <b>{values.awsAccountId}</b>
          </Box>
          <Box as="li" color="gray-300" mb={3}>
            3. Find the stack <b>{initialValues.initialStackName}</b>
          </Box>
          <Box as="li" color="gray-300" mb={3}>
            4. Press <b>Update</b>, choose <b>Replace current template</b>
          </Box>
          <Box as="li" color="gray-300" mb={3}>
            5. Press <b>Next</b> and finally click on <b>Update</b>
          </Box>
        </Box>
        <Text color="gray-300" mt={10} mb={2} fontSize="medium">
          Alternatively, you can update your stack through the AWS CLI
        </Text>
      </React.Fragment>
    );
  };

  return (
    <Box maxWidth={700} mx="auto">
      {renderContent()}
    </Box>
  );
};

export default StackDeployment;
