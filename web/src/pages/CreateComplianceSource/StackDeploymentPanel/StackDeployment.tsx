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

import { Text, Box, Heading, Alert, Spinner } from 'pouncejs';
import React from 'react';
import { INTEGRATION_TYPES } from 'Source/constants';
import { extractErrorMessage } from 'Helpers/utils';
import { useFormikContext } from 'formik';
import { useGetCfnTemplate } from './graphql/getCfnTemplate.generated';
import { CreateInfraSourceValues } from '../CreateComplianceSource';

const StackDeployment: React.FC = () => {
  const downloadAnchor = React.useRef<HTMLAnchorElement>(null);
  const { values, setStatus } = useFormikContext<CreateInfraSourceValues>();
  const { data, loading, error } = useGetCfnTemplate({
    fetchPolicy: 'no-cache',
    variables: {
      input: {
        awsAccountId: values.awsAccountId,
        remediationEnabled: values.remediationEnabled,
        cweEnabled: values.cweEnabled,
        integrationType: INTEGRATION_TYPES.AWS_INFRA,
      },
    },
  });

  React.useEffect(() => {
    if (data) {
      const blob = new Blob([data.getIntegrationTemplate.body], {
        type: 'text/yaml;charset=utf-8',
      });

      const downloadUrl = URL.createObjectURL(blob);
      downloadAnchor.current.setAttribute('href', downloadUrl);
    }
  }, [downloadAnchor, data]);

  return (
    <Box>
      <Heading size="medium" m="auto" mb={10} color="grey400">
        Deploy your configured stack
      </Heading>
      {error && (
        <Alert
          variant="error"
          title="Couldn't generate a cloudformation template"
          description={extractErrorMessage(error)}
        />
      )}
      <Text size="large" color="grey200" is="p" mb={6}>
        Before we can proceed, you must deploy the auto-generated Cloudformation file to your
        related AWS account.
        <br />
        <br />
      </Text>
      <Text size="large" color="blue300">
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
            Download Stack
          </a>
        )}
      </Text>
    </Box>
  );
};

export default StackDeployment;
