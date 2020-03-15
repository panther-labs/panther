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
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';
import { extractErrorMessage } from 'Helpers/utils';
import { useGetCfnTemplate } from './graphql/getCfnTemplate.generated';

const StackDeployment: React.FC = () => {
  const { data, loading, error } = useGetCfnTemplate({
    fetchPolicy: 'no-cache',
  });

  if (loading) {
    return <Spinner size="medium" />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't generate a cloudformation template"
        description={extractErrorMessage(error)}
      />
    );
  }

  return (
    <Box>
      <Heading size="medium" m="auto" mb={2} color="grey400">
        Deploy your configured stack
      </Heading>
      <Text size="large" color="grey200" mb={10} is="p">
        Deploy the Cloudformation stack that we created for you
      </Text>
      {loading && <Spinner size="medium" />}
      {error && (
        <Alert
          variant="error"
          title="Couldn't generate a cloudformation template"
          description={extractErrorMessage(error)}
        />
      )}
      {data && (
        <Text size="large" color="grey200" is="p">
          By clicking the button below, you will be redirected to the CloudFormation console to
          launch a stack in your account.
          <br />
          <br />
          <pre>{data.getIntegrationTemplate.body}</pre>
          <a
            target="_blank"
            rel="noopener noreferrer"
            href={`${PANTHER_SCHEMA_DOCS_LINK}/amazon-web-services/aws-setup/scanning`}
          >
            documentation
          </a>{' '}
          to learn more about this functionality.
        </Text>
      )}
    </Box>
  );
};

export default StackDeployment;
