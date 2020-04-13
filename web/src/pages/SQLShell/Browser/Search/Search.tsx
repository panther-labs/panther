import React from 'react';
import { TextInput } from 'pouncejs';
import { useSQLShellContext } from '../../SQLShellContext';

const Search: React.FC = () => {
  const { searchValue, setSearchValue, selectedDatabase } = useSQLShellContext();
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
