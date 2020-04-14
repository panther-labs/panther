import React from 'react';

interface SQLShellContextValue {
  selectedDatabase: string | null;
  selectedTable: string | null;
  selectedColumn: string | null;
  searchValue: string;
  globalErrorMessage: string;
  selectDatabase: (db: string) => void;
  selectTable: (table: string) => void;
  selectColumn: (column: string) => void;
  setSearchValue: (val: string) => void;
  setGlobalErrorMessage: (val: string) => void;
}

const SQLShellContext = React.createContext<SQLShellContextValue>(undefined);

export const SQLShellContextProvider: React.FC = ({ children }) => {
  const [selectedDatabase, selectDatabase] = React.useState<string>(null);
  const [selectedTable, selectTable] = React.useState<string>(null);
  const [selectedColumn, selectColumn] = React.useState<string>(null);
  const [searchValue, setSearchValue] = React.useState<string>('');
  const [globalErrorMessage, setGlobalErrorMessage] = React.useState('');

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
      globalErrorMessage,
      setGlobalErrorMessage,
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
      globalErrorMessage,
      setGlobalErrorMessage,
    ]
  );

  React.useEffect(() => {
    selectTable(null);
  }, [selectedDatabase, selectTable, setSearchValue]);

  React.useEffect(() => {
    selectColumn(null);
    setSearchValue('');
  }, [selectedTable, selectColumn]);

  return <SQLShellContext.Provider value={contextValue}>{children}</SQLShellContext.Provider>;
};

export const useSQLShellContext = () => React.useContext(SQLShellContext);

export const withSQLShellContext = (Component: React.FC) => props => (
  <SQLShellContextProvider>
    <Component {...props} />
  </SQLShellContextProvider>
);
