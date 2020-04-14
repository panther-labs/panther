import React from 'react';
import { TextInput } from 'pouncejs';
import { useSQLShellContext } from '../../SQLShellContext';

const Search: React.FC = () => {
  const {
    state: { searchValue, selectedDatabase },
    dispatch,
  } = useSQLShellContext();

  return (
    <TextInput
      label="Filter"
      value={searchValue}
      placeholder="Search for a table or column..."
      disabled={!selectedDatabase}
      onChange={e =>
        dispatch({ type: 'SEARCH_DATABASE', payload: { searchValue: e.target.value } })
      }
    />
  );
};

export default Search;
