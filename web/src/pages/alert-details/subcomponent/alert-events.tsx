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
import PaginationControls from 'Components/utils/table-pagination-controls';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';

interface AlertEventsProps {
  events: string[];
  total: number;
  fetchMore: () => void;
}

const AlertEvents: React.FC<AlertEventsProps> = ({ events, total, fetchMore }) => {
  const [eventIndex, setEventIndex] = React.useState(0);

  React.useEffect(() => {
    if (eventIndex === events.length - DEFAULT_LARGE_PAGE_SIZE) {
      fetchMore();
    }
  }, [eventIndex]);

  return (
    <Panel
      size="large"
      title="Triggered Events"
      actions={
        <PaginationControls page={eventIndex + 1} totalPages={total} onPageChange={setEventIndex} />
      }
    >
      <JsonViewer data={JSON.parse(JSON.parse(events[eventIndex]))} />
    </Panel>
  );
};

export default AlertEvents;
