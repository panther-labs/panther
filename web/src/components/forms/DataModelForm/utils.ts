import { parseYaml } from 'Helpers/utils';
import { DataModelMapping } from 'Generated/schema';

export const convertYamlToDataModelMappings = async (yaml: string) => {
  try {
    const mappingsArray = (await parseYaml(yaml)) as DataModelMapping[];
    if (!Array.isArray(mappingsArray)) {
      return Promise.reject(new Error("Couldn't find a list of mappings"));
    }

    if (!mappingsArray.every(mapping => 'Name' in mapping)) {
      return Promise.reject(new Error('`Name` is a mandatory property in all mappings'));
    }

    if (!mappingsArray.every(mapping => 'Path' in mapping || 'Method' in mapping)) {
      return Promise.reject(new Error('Each mapping must specify either a `Path` or a `Method`'));
    }

    return Promise.resolve(mappingsArray);
  } catch (err) {
    return Promise.reject(err);
  }
};
