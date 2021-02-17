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
import { AnalysisPack, AnalysisPackVersion } from 'Generated/schema';
import { Button, Flex, Box, Combobox } from 'pouncejs';
import { compareSemanticVersion } from 'Helpers/utils';

interface UpdateVersionProps {
  pack: Pick<AnalysisPack, 'availableVersions' | 'packVersion' | 'enabled'>;
  onPatch: (values: UpdateVersionFormValues) => void;
}

export interface UpdateVersionFormValues {
  packVersion: {
    id: number;
    semVer: string;
  };
}

const versionToString = v => v.semVer;

const UpdateVersion: React.FC<UpdateVersionProps> = ({
  pack: { enabled, availableVersions, packVersion: current },
  onPatch,
}) => {
  const sortedVersions = [...availableVersions];
  sortedVersions.sort((a, b) => compareSemanticVersion(b.semVer, a.semVer));
  const [selectedVersion, setSelectedVersion] = React.useState<AnalysisPackVersion>(
    sortedVersions[0]
  );

  return (
    <Flex spacing={4}>
      <Box width={100}>
        <Combobox
          label="Version"
          value={selectedVersion}
          disabled={!enabled}
          onChange={setSelectedVersion}
          items={sortedVersions}
          itemToString={versionToString}
        />
      </Box>
      <Box width={130}>
        {compareSemanticVersion(selectedVersion.semVer, current.semVer) >= 0 ? (
          <Button
            disabled={!enabled || selectedVersion.semVer === current.semVer}
            onClick={() => onPatch({ packVersion: selectedVersion })}
          >
            Update Pack
          </Button>
        ) : (
          <Button
            variantColor="violet"
            disabled={!enabled || selectedVersion.semVer === current.semVer}
            onClick={() => onPatch({ packVersion: selectedVersion })}
          >
            Revert Pack
          </Button>
        )}
      </Box>
    </Flex>
  );
};

export default React.memo(UpdateVersion);
