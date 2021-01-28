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
import JsonViewer from 'Components/JsonViewer';
import { Box, Card, Flex, Heading, Icon, Tooltip } from 'pouncejs';
import { AlertDetailsRuleInfo } from 'Generated/schema';
import { TableControlsPagination as PaginationControls } from 'Components/utils/TableControls';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { toPlural } from 'Helpers/utils';
import { AlertDetails } from '../../graphql/alertDetails.generated';

// Given an event received as a string, this function converts it to JSON
const parseAlertEventToJson = (event: string) => {
  return JSON.parse(JSON.parse(event));
};

interface AlertDetailsEventsProps {
  alert: AlertDetails['alert'];
  fetchMore: () => void;
}

const AlertDetailsEvents: React.FC<AlertDetailsEventsProps> = ({ alert, fetchMore }) => {
  // because we are going to use that in PaginationControls we are starting an indexing starting
  // from 1 instead of 0. That's why we are using `eventDisplayIndex - 1` when selecting the proper event.
  // Normally the `PaginationControls` are used for displaying pages so they are built with a
  // 1-based indexing in mind
  const [eventDisplayIndex, setEventDisplayIndex] = React.useState(1);

  const detectionData = alert.detection as AlertDetailsRuleInfo;
  React.useEffect(() => {
    if (eventDisplayIndex - 1 === detectionData.events.length - DEFAULT_LARGE_PAGE_SIZE) {
      fetchMore();
    }
  }, [eventDisplayIndex, detectionData.events.length]);

  return (
    <Flex direction="column" spacing={6}>
      <Flex justify="space-between" align="center">
        <Flex align="center" spacing={2}>
          <Heading size="x-small">
            <b>{detectionData.eventsMatched}</b> Triggered{' '}
            {toPlural('Event', detectionData.eventsMatched)}
          </Heading>
          <Tooltip
            content={
              <Box maxWidth={300}>
                Each triggered event contains a set of extended metadata for a log entry that was
                matched against your rule
              </Box>
            }
          >
            <Icon type="info" size="medium" />
          </Tooltip>
        </Flex>
        <PaginationControls
          page={eventDisplayIndex}
          totalPages={detectionData.eventsMatched}
          onPageChange={setEventDisplayIndex}
        />
      </Flex>
      <Card variant="dark" p={6}>
        <JsonViewer data={parseAlertEventToJson(detectionData.events[eventDisplayIndex - 1])} />
      </Card>
    </Flex>
  );
};

export default React.memo(AlertDetailsEvents);
