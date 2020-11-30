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

import { Text, Box, Flex, SimpleGrid, Card, Img, Heading, Button, useSnackbar } from 'pouncejs';
import React from 'react';
import { FULL_PANTHER_VERSION } from 'Source/constants';
import { downloadData, toStackNameFormat } from 'Helpers/utils';
import { useFormikContext } from 'formik';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { pantherConfig } from 'Source/config';
import lightningIllustration from 'Assets/illustrations/lightning.svg';
import cogsIllustration from 'Assets/illustrations/cogs.svg';
import LinkButton from 'Components/buttons/LinkButton';
import { useGetLogCfnTemplate } from './graphql/getLogCfnTemplate.generated';
import { S3LogSourceWizardValues } from '../S3LogSourceWizard';

const StackDeployment: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { goToNextStep } = useWizardContext();
  const { initialValues, values } = useFormikContext<S3LogSourceWizardValues>();
  const { data, loading } = useGetLogCfnTemplate({
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
    onError: () => pushSnackbar({ variant: 'error', title: 'Failed to generate CFN template' }),
  });

  const { stackName, body } = data?.getS3LogIntegrationTemplate ?? {};
  const cfnConsoleLink =
    `https://${pantherConfig.AWS_REGION}.console.aws.amazon.com/cloudformation/home?region=${pantherConfig.AWS_REGION}#/stacks/create/review` +
    `?templateURL=https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-log-analysis-iam/${FULL_PANTHER_VERSION}/template.yml` +
    `&stackName=${stackName}` +
    `&param_MasterAccountId=${pantherConfig.AWS_ACCOUNT_ID}` +
    `&param_RoleSuffix=${toStackNameFormat(values.integrationLabel)}` +
    `&param_S3Bucket=${values.s3Bucket}` +
    `&param_S3Prefix=${values.s3Prefix}` +
    `&param_KmsKey=${values.kmsKey}`;

  return (
    <WizardPanel>
      <WizardPanel.Heading
        title="Deploy Panther's IAM roles"
        subtitle="These roles will allow Panther to read your logs from the S3 Bucket"
      />
      <SimpleGrid columns={2} gap={5} px={80} mx="auto" mb={6}>
        <Card variant="dark" p={6}>
          <Flex direction="column" align="center" spacing={4}>
            <Img src={lightningIllustration} alt="Lightning" nativeWidth={40} nativeHeight={40} />
            <Heading as="h4" size="x-small">
              Using Cloudformation Console
            </Heading>
            <Text fontSize="small-medium" color="gray-300" textAlign="center">
              Deploy our autogenerated Cloudformation template to the AWS account that you are
              onboarding, to generate the necessary ReadOnly IAM Roles. After deployment please
              continue with setup completion.
              {initialValues.integrationId && (
                <Box as="b" mt={3} display="block">
                  Make sure you select Update and then Replace current template
                </Box>
              )}
            </Text>
            <LinkButton external to={cfnConsoleLink} variantColor="teal">
              Launch Console
            </LinkButton>
          </Flex>
        </Card>
        <Card variant="dark" p={6}>
          <Flex direction="column" align="center" spacing={4}>
            <Img src={cogsIllustration} alt="Cogssn" nativeWidth={40} nativeHeight={40} />
            <Heading as="h4" size="x-small">
              Using the AWS CLI
            </Heading>
            <Text fontSize="small-medium" color="gray-300" textAlign="center">
              Download the autogenerated Cloudformation template and deploy it to the AWS account
              that you are onboarding via the given CLI/SDK. After deployment please continue with
              setup completion.
              {initialValues.integrationId && (
                <Box as="b" mt={3} display="block">
                  Make sure you update the template of the existing stack
                </Box>
              )}
            </Text>
            <Button
              icon="download"
              variantColor="violet"
              loading={loading}
              disabled={loading}
              onClick={() => downloadData(body, `${stackName}.yaml`)}
            >
              Get template file
            </Button>
          </Flex>
        </Card>
      </SimpleGrid>
      <WizardPanel.Actions>
        <WizardPanel.ActionPrev />
        <Flex spacing={4} direction="column" align="center">
          <Text fontSize="small">Already have your IAM roles setup?</Text>
          <Button variant="outline" variantColor="navyblue" onClick={goToNextStep}>
            Continue
          </Button>
        </Flex>
      </WizardPanel.Actions>
    </WizardPanel>
  );
};

export default StackDeployment;
