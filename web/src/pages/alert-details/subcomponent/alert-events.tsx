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

import React from 'react';
import JsonViewer from 'Components/json-viewer';
import Panel from 'Components/panel';
import { Flex, Icon, IconButton, Label } from 'pouncejs';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';

interface AlertEventsProps {
  events: string[];
  total: number;
  fetchMore: () => void;
}

const AlertEvents: React.FC<AlertEventsProps> = ({ events, total, fetchMore }) => {
  const [eventIndex, setEventIndex] = React.useState(0);

  return (
    <Panel
      size="large"
      title="Triggered Events"
      actions={
        <Flex alignItems="center" justifyContent="center">
          <Flex mr={9} alignItems="center">
            <IconButton
              variant="default"
              disabled={eventIndex <= 0}
              onClick={() => setEventIndex(eventIndex - 1)}
            >
              <Icon size="large" type="chevron-left" />
            </IconButton>
            <Label size="large" mx={4} color="grey400">
              {eventIndex + 1} of {total}
            </Label>
            <IconButton
              variant="default"
              disabled={eventIndex >= total - 1}
              onClick={() => {
                if (eventIndex > events.length - DEFAULT_LARGE_PAGE_SIZE) {
                  fetchMore();
                }

                setEventIndex(eventIndex + 1);
              }}
            >
              <Icon size="large" type="chevron-right" />
            </IconButton>
          </Flex>
        </Flex>
      }
    >
      <JsonViewer data={JSON.parse(JSON.parse(events[eventIndex]))} />
    </Panel>
  );
};

export default AlertEvents;
