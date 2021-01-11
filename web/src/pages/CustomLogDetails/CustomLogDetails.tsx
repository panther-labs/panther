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

import React from 'react';
import { Alert, Box, Flex, Button, Card, Heading, Link, SimpleGrid, Text } from 'pouncejs';
import { compose } from 'Helpers/compose';
import withSEO from 'Hoc/withSEO';
import { ErrorCodeEnum } from 'Generated/schema';
import Page404 from 'Pages/404';
import Editor from 'Components/Editor';
import Breadcrumbs from 'Components/Breadcrumbs';
import useRouter from 'Hooks/useRouter';
import LinkButton from 'Components/buttons/LinkButton';
import urls from 'Source/urls';
import useModal from 'Hooks/useModal';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum } from 'Helpers/analytics';
import { extractErrorMessage } from 'Helpers/utils';
import TablePlaceholder from 'Components/TablePlaceholder';
import { MODALS } from 'Components/utils/Modal';
import { useGetCustomLogDetails } from './graphql/getCustomLogDetails.generated';

const CustomLogDetails: React.FC = () => {
  useTrackPageView(PageViewEnum.CustomLogDetails);

  const { showModal } = useModal();
  const { match: { params: { logType } } } = useRouter<{ logType: string }>(); // prettier-ignore

  const { data, loading, error: uncontrolledError } = useGetCustomLogDetails({
    variables: { input: { logType } },
  });

  if (loading) {
    return (
      <Card p={6}>
        <TablePlaceholder />
      </Card>
    );
  }

  if (uncontrolledError) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your custom schema"
        description={extractErrorMessage(uncontrolledError)}
      />
    );
  }

  const { record: customLog, error: controlledError } = data.getCustomLog;
  if (controlledError) {
    if (controlledError.code === ErrorCodeEnum.NotFound) {
      return <Page404 />;
    }

    return (
      <Alert
        variant="error"
        title="Couldn't load your custom schema"
        description={controlledError.message}
      />
    );
  }

  return (
    <Card p={6} mb={6}>
      <Breadcrumbs.Actions>
        <Flex spacing={4} justify="flex-end">
          <LinkButton icon="pencil" to={urls.logAnalysis.customLogs.edit(customLog.logType)}>
            Edit Log
          </LinkButton>
          <Button
            variantColor="red"
            icon="trash"
            onClick={() => {
              showModal({
                modal: MODALS.DELETE_CUSTOM_LOG,
                props: { customLog },
              });
            }}
          >
            Delete Log
          </Button>
        </Flex>
      </Breadcrumbs.Actions>

      <Heading mb={6} fontWeight="bold">
        {customLog.logType}
      </Heading>
      <Card variant="dark" as="section" p={4} mb={4}>
        <SimpleGrid columns={2}>
          <Box>
            <Box aria-describedby="description" fontSize="small-medium" color="navyblue-100" mb={2}>
              Description
            </Box>
            {customLog.description ? (
              <Text id="description">{customLog.description}</Text>
            ) : (
              <Text id="description" color="navyblue-200">
                No description found
              </Text>
            )}
          </Box>
          <Box>
            <Box
              aria-describedby="referenceURL"
              fontSize="small-medium"
              color="navyblue-100"
              mb={2}
            >
              Reference URL
            </Box>
            {customLog.referenceURL ? (
              <Link external id="referenceURL">
                {customLog.referenceURL}
              </Link>
            ) : (
              <Text id="referenceURL" color="navyblue-200">
                No reference URL provided
              </Text>
            )}
          </Box>
        </SimpleGrid>
      </Card>
      <Card variant="dark" px={4} py={5} as="section">
        <Heading size="x-small" mb={5}>
          Event Schema
        </Heading>
        <Editor readOnly width="100%" mode="yaml" value={customLog.logSpec} />
      </Card>
    </Card>
  );
};

export default compose(withSEO({ title: ({ match }) => match.params.logType }))(CustomLogDetails);
