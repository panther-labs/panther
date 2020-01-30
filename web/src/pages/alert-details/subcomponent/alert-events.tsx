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
  // because we are going to use that in PaginationControls we are starting an indexing starting
  // from 1 instead of 0. That's why we are using `eventDisplayIndex - 1` when selecting the proper event.
  // Normally the `PaginationControls` are used for displaying pages so they are built with a
  // 1-based indexing in mind
  const [eventDisplayIndex, setEventDisplayIndex] = React.useState(1);

  React.useEffect(() => {
    if (eventDisplayIndex - 1 === events.length - DEFAULT_LARGE_PAGE_SIZE) {
      fetchMore();
    }
  }, [eventDisplayIndex]);

  return (
    <Panel
      size="large"
      title="Triggered Events"
      actions={
        <PaginationControls
          page={eventDisplayIndex}
          totalPages={total}
          onPageChange={setEventDisplayIndex}
        />
      }
    >
      <JsonViewer data={JSON.parse(JSON.parse(events[eventDisplayIndex - 1]))} />
    </Panel>
  );
};

export default React.memo(AlertEvents);
