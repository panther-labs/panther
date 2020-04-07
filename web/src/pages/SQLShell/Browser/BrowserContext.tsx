import React from 'react';

interface BrowserContextValue {
  selectedDatabase: string | null;
  selectedTable: string | null;
  selectedColumn: string | null;
  searchValue: string;
  selectDatabase: (db: string) => void;
  selectTable: (table: string) => void;
  selectColumn: (column: string) => void;
  setSearchValue: (val: string) => void;
}

const BrowserContext = React.createContext<BrowserContextValue>(undefined);

export const BrowserContextProvider: React.FC = ({ children }) => {
  const [selectedDatabase, selectDatabase] = React.useState<string>(null);
  const [selectedTable, selectTable] = React.useState<string>(null);
  const [selectedColumn, selectColumn] = React.useState<string>(null);
  const [searchValue, setSearchValue] = React.useState<string>('');

  const contextValue = React.useMemo(
    () => ({
      selectedDatabase,
      selectedTable,
      selectedColumn,
      selectTable,
      selectDatabase,
      selectColumn,
      searchValue,
      setSearchValue,
    }),
    [
      selectedDatabase,
      selectDatabase,
      selectedTable,
      selectTable,
      selectedColumn,
      selectColumn,
      searchValue,
      setSearchValue,
    ]
  );

  React.useEffect(() => {
    selectTable(null);
  }, [selectedDatabase, selectTable, setSearchValue]);

  React.useEffect(() => {
    selectColumn(null);
    setSearchValue('');
  }, [selectedTable, selectColumn]);

  return <BrowserContext.Provider value={contextValue}>{children}</BrowserContext.Provider>;
};

export const useBrowserContext = () => React.useContext(BrowserContext);

export const withBrowserContext = (Component: React.FC) => props => (
  <BrowserContextProvider>
    <Component {...props} />
  </BrowserContextProvider>
);
