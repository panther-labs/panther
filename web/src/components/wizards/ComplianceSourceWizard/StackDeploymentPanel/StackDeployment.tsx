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

import { Text, Box, Heading, Spinner } from 'pouncejs';
import React from 'react';
import { extractErrorMessage, getComplianceIntegrationStackName } from 'Helpers/utils';
import { useFormikContext } from 'formik';
import { useGetComplianceCfnTemplate } from './graphql/getComplianceCfnTemplate.generated';
import { ComplianceSourceWizardValues } from '../ComplianceSourceWizard';

const StackDeployment: React.FC = () => {
  const downloadAnchor = React.useRef<HTMLAnchorElement>(null);
  const { initialValues } = useFormikContext<ComplianceSourceWizardValues>();
  const { values, setStatus } = useFormikContext<ComplianceSourceWizardValues>();
  const { data, loading, error } = useGetComplianceCfnTemplate({
    fetchPolicy: 'no-cache',
    variables: {
      input: {
        awsAccountId: values.awsAccountId,
        remediationEnabled: values.remediationEnabled,
        cweEnabled: values.cweEnabled,
      },
    },
  });

  React.useEffect(() => {
    if (data) {
      const blob = new Blob([data.getComplianceIntegrationTemplate.body], {
        type: 'text/yaml;charset=utf-8',
      });

      const downloadUrl = URL.createObjectURL(blob);
      downloadAnchor.current.setAttribute('href', downloadUrl);
    }
  }, [downloadAnchor, data]);

  const stackName = getComplianceIntegrationStackName();
  const cfnConsoleLink =
    `https://${process.env.AWS_REGION}.console.aws.amazon.com/cloudformation/home?region=${process.env.AWS_REGION}#/stacks/create/review` +
    `?templateURL=https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudsec-iam/v1.0.0/template.yml` +
    `&stackName=${stackName}` +
    `&param_MasterAccountId=${process.env.AWS_ACCOUNT_ID}` +
    `&param_DeployCloudWatchEventSetup=${values.cweEnabled}` +
    `&param_DeployRemediation=${values.remediationEnabled}`;

  const renderDownloadTemplateLink = () => {
    if (error) {
      return (
        <Text size="large" color="red300">
          Couldn{"'"}t generate a Cloudformation template. {extractErrorMessage(error)}
        </Text>
      );
    }

    return (
      <Text size="large" color="blue300" is="span">
        {loading ? (
          <Spinner size="small" />
        ) : (
          <a
            href="#"
            title="Download Cloudformation template"
            download={`cloud-security-${values.awsAccountId}.yaml`}
            ref={downloadAnchor}
            onClick={() => setStatus({ cfnTemplateDownloaded: true })}
          >
            Download template
          </a>
        )}
      </Text>
    );
  };

  return (
    <Box>
      <Heading size="medium" m="auto" mb={10} color="grey400">
        Deploy your configured stack
      </Heading>
      {!initialValues.integrationId ? (
        <React.Fragment>
          <Text size="large" color="grey200" is="p" mb={2}>
            To proceed, you must deploy the generated Cloudformation template to the account{' '}
            <b>{values.awsAccountId}</b>. This will generate the necessary IAM Roles.
          </Text>
          <Text
            size="large"
            color="blue300"
            is="a"
            target="_blank"
            rel="noopener noreferrer"
            title="Launch Cloudformation console"
            href={cfnConsoleLink}
            onClick={() => setStatus({ cfnTemplateDownloaded: true })}
          >
            Launch console
          </Text>
          <Text size="large" color="grey200" is="p" mt={10} mb={2}>
            Alternatively, you can download it and deploy it through the AWS CLI with the stack name{' '}
            <b>{stackName}</b>
          </Text>
          {renderDownloadTemplateLink()}
        </React.Fragment>
      ) : (
        <React.Fragment>
          <Text size="large" color="grey200" is="p" mb={6}>
            To proceed, please deploy the updated Cloudformation template to your related AWS
            account. This will update any previous IAM Roles.
          </Text>
          <Box is="ol">
            <Text size="large" is="li" color="grey200" mb={3}>
              1. {renderDownloadTemplateLink()}
            </Text>
            <Text size="large" is="li" color="grey200" mb={3}>
              2. Log into your
              <Text
                ml={1}
                size="large"
                color="blue300"
                is="a"
                target="_blank"
                rel="noopener noreferrer"
                title="Launch Cloudformation console"
                href={`https://${process.env.AWS_REGION}.console.aws.amazon.com/cloudformation/home`}
              >
                Cloudformation console
              </Text>{' '}
              of the account <b>{values.awsAccountId}</b>
            </Text>
            <Text size="large" is="li" color="grey200" mb={3}>
              3. Find the stack <b>{stackName}</b> (you may need to change regions)
            </Text>
            <Text size="large" is="li" color="grey200" mb={3}>
              4. Press <b>Update</b>, choose <b>Replace current template</b>
            </Text>
            <Text size="large" is="li" color="grey200" mb={3}>
              5. Press <b>Next</b> and finally click on <b>Update</b>
            </Text>
          </Box>
          <Text size="large" color="grey200" is="p" mt={10} mb={2}>
            Alternatively, you can update your stack through the AWS CLI
          </Text>
        </React.Fragment>
      )}
    </Box>
  );
};

export default StackDeployment;
