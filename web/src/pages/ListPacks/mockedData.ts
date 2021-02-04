// TODO: Remove this file
import { buildPack, buildPackVersion } from '../../../__tests__/__mocks__/builders.generated';

const packVersion1 = buildPackVersion({ id: '123', name: 'v2.1.3' });
const packVersion2 = buildPackVersion({ id: '456', name: 'v2.1.0' });
const packVersion3 = buildPackVersion({ id: '124', name: 'v2.0.0' });
const packVersion4 = buildPackVersion({ id: '31231', name: 'v1.21.1' });
const packVersion5 = buildPackVersion({ id: '3412', name: 'v1.21.0' });

const availableVersions = [packVersion3, packVersion4, packVersion1, packVersion2, packVersion5];

// const detectionPattern1 = buildPackDetectionsPatterns();
// const detectionTypes1 = buildDetectionTypes();

const pack1 = buildPack({
  id: 'pack1',
  displayName: 'Pack 1',
  updateAvailable: true,
  packVersion: packVersion4,
  availableVersions,
});
const pack2 = buildPack({
  id: 'pack2',
  enabled: false,
  updateAvailable: false,
  packVersion: packVersion1,
  availableVersions,
});
const pack3 = buildPack({
  id: 'pack3',
  packVersion: packVersion1,
  updateAvailable: false,
  availableVersions,
});

export default { packs: [pack1, pack2, pack3] };
