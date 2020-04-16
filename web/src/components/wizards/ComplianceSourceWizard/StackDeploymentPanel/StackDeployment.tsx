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

import { Text, Box, Heading, Spinner, Link } from 'pouncejs';
import React from 'react';
import { extractErrorMessage } from 'Helpers/utils';
import { useFormikContext } from 'formik';
import { useGetComplianceCfnTemplate } from './graphql/getComplianceCfnTemplate.generated';
import { ComplianceSourceWizardValues } from '../ComplianceSourceWizard';

const StackDeployment: React.FC = () => {
  const { initialValues, values, setStatus } = useFormikContext<ComplianceSourceWizardValues>();
  const { data, loading, error } = useGetComplianceCfnTemplate({
    variables: {
      input: {
        awsAccountId: values.awsAccountId,
        integrationLabel: values.integrationLabel,
        remediationEnabled: values.remediationEnabled,
        cweEnabled: values.cweEnabled,
      },
    },
  });

  const downloadRef = React.useCallback(
    node => {
      if (data && node) {
        const blob = new Blob([data.getComplianceIntegrationTemplate.body], {
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

    const { stackName } = data.getComplianceIntegrationTemplate;
    const downloadTemplateLink = (
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
    );

    if (!initialValues.integrationId) {
      const cfnConsoleLink =
        `https://${process.env.AWS_REGION}.console.aws.amazon.com/cloudformation/home?region=${process.env.AWS_REGION}#/stacks/create/review` +
        `?templateURL=https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudsec-iam/v1.0.0/template.yml` +
        `&stackName=${stackName}` +
        `&param_MasterAccountRegion=${process.env.AWS_REGION}` +
        `&param_MasterAccountId=${process.env.AWS_ACCOUNT_ID}` +
        `&param_DeployCloudWatchEventSetup=${values.cweEnabled}` +
        `&param_DeployRemediation=${values.remediationEnabled}`;

      return (
        <React.Fragment>
          <Text size="large" color="grey200" as="p" mt={2} mb={2}>
            The quickest way to do it, is through the AWS console
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
          {downloadTemplateLink}
        </React.Fragment>
      );
    }

    return (
      <React.Fragment>
        <Box as="ol">
          <Text size="large" as="li" color="grey200" mb={3}>
            1. {downloadTemplateLink}
          </Text>
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
            3. Find the stack <b>{stackName}</b>
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

  return (
    <Box>
      <Heading size="medium" m="auto" mb={2} color="grey400">
        Deploy your configured stack
      </Heading>
      <Text size="large" color="grey200" as="p" mb={10}>
        To proceed, you must deploy the generated Cloudformation template to the AWS account{' '}
        <b>{values.awsAccountId}</b>.{' '}
        {!initialValues.integrationId
          ? 'This will generate the necessary IAM Roles.'
          : 'This will update any previous IAM Roles.'}
      </Text>
      {renderContent()}
    </Box>
  );
};

export default StackDeployment;
