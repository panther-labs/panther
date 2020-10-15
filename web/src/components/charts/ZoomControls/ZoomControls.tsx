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
import { Flex } from 'pouncejs';
import ZoomButton from './ZoomButton';

interface ScaleControlsProps {
  onZoom: (boolean) => void;
  onReset: () => void;
}

const ScaleControls: React.FC<ScaleControlsProps> = ({ onZoom, onReset }) => {
  const [zoomEnabled, setZoomEnabled] = React.useState(false);
  return (
    <Flex spacing={2} zIndex={5}>
      <ZoomButton
        title="ZOOM"
        selected={zoomEnabled}
        onClick={() => {
          onZoom(zoomEnabled);
          setZoomEnabled(!zoomEnabled);
        }}
      />
      <ZoomButton title="RESET" onClick={onReset} />
    </Flex>
  );
};

export default ScaleControls;
