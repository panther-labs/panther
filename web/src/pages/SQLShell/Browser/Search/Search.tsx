import React from 'react';
import { TextInput } from 'pouncejs';
import { useBrowserContext } from '../BrowserContext';

const Search: React.FC = () => {
  const { searchValue, setSearchValue, selectedDatabase } = useBrowserContext();
  return (
    <TextInput
      label="Filter"
      onChange={e => setSearchValue(e.target.value)}
      value={searchValue}
      placeholder="Search for a table or column..."
      disabled={!selectedDatabase}
    />
  );
};

export default Search;
