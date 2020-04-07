import React from 'react';

interface BrowserContextValue {
  selectedDatabase: string | null;
  selectDatabase: (db: string) => void;
  selectedTable: string | null;
  selectTable: (table: string) => void;
  selectedColumn: string | null;
  selectColumn: (column: string) => void;
}

const BrowserContext = React.createContext<BrowserContextValue>(undefined);

export const BrowserContextProvider: React.FC = ({ children }) => {
  const [selectedDatabase, selectDatabase] = React.useState<string>(null);
  const [selectedTable, selectTable] = React.useState<string>(null);
  const [selectedColumn, selectColumn] = React.useState<string>(null);

  const contextValue = React.useMemo(
    () => ({
      selectedDatabase,
      selectedTable,
      selectedColumn,
      selectTable,
      selectDatabase,
      selectColumn,
    }),
    [selectedDatabase, selectDatabase, selectedTable, selectTable, selectedColumn, selectColumn]
  );

  React.useEffect(() => {
    selectTable(null);
  }, [selectedDatabase, selectTable]);

  React.useEffect(() => {
    selectColumn(null);
  }, [selectedTable, selectColumn]);

  return <BrowserContext.Provider value={contextValue}>{children}</BrowserContext.Provider>;
};

export const useBrowserContext = () => React.useContext(BrowserContext);

export const withBrowserContext = (Component: React.FC) => props => (
  <BrowserContextProvider>
    <Component {...props} />
  </BrowserContextProvider>
);
