/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Alert, Flex } from 'pouncejs';
import urls from 'Source/urls';
import Panel from 'Components/Panel';
import LinkButton from 'Components/buttons/LinkButton';
import { compose } from 'Helpers/compose';
import withSEO from 'Hoc/withSEO';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage, slugify } from 'Helpers/utils';
import { useListCustomLogSchemas } from './graphql/listCustomLogSchemas.generated';
import CustomLogCard from './CustomLogCard';
import EmptyDataFallback from './EmptyDataFallback';

const ListCustomLogs: React.FC = () => {
  const { data, loading, error } = useListCustomLogSchemas();

  return (
    <Panel
      title="Custom Schemas"
      actions={
        <LinkButton to={urls.logAnalysis.customLogs.create()} icon="add">
          New Schema
        </LinkButton>
      }
    >
      {loading && <TablePlaceholder />}
      {error && (
        <Alert
          variant="error"
          title="Couldn't load your custom schemas"
          description={
            extractErrorMessage(error) ||
            'There was an error while attempting to list your custom schemas'
          }
        />
      )}
      {data &&
        (data.listCustomLogs.length > 0 ? (
          <Flex direction="column" spacing={4}>
            {data.listCustomLogs.map(customLog => (
              <CustomLogCard key={slugify(customLog.logType)} customLog={customLog} />
            ))}
          </Flex>
        ) : (
          <EmptyDataFallback />
        ))}
    </Panel>
  );
};

export default compose(withSEO({ title: 'Custom Schemas' }))(ListCustomLogs);
