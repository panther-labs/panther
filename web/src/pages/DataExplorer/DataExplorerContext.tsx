import React from 'react';
import useUrlParams from 'Hooks/useUrlParams';
import storage from 'Helpers/storage';

// A key to help persist the selected database in order to restore it whenever we don't have one
// explicitly specified through the URL
const SELECTED_DATABASE_STORAGE_KEY = 'panther.dataAnalytics.dataExplorer.selectedDatabase';

type State = {
  selectedDatabase: string | null;
  selectedTable: string | null;
  selectedColumn: string | null;
  searchValue: string;
  globalErrorMessage: string;
  queryId?: string | null;
  queryStatus: 'provisioning' | 'errored' | 'running' | 'succeeded' | null;
};

type Action<T, P = never> = {
  type: T;
  payload?: P;
};

type SelectDatabaseAction = Action<'SELECT_DATABASE', { database: string }>;
type SelectTableAction = Action<'SELECT_TABLE', { table: string }>;
type SelectColumnAction = Action<'SELECT_COLUMN', { column: string }>;
type SearchAction = Action<'SEARCH_DATABASE', { searchValue: string }>;
type MarkQueryAsProvisioning = Action<'QUERY_PROVISIONING'>;
type MarkQueryAsErrored = Action<'QUERY_ERRORED', { message: string }>;
type MarkQueryAsRunning = Action<'QUERY_RUNNING', { queryId: string }>;
type MarkQueryAsCanceled = Action<'QUERY_CANCELED'>;
type MarkQueryAsSuccessful = Action<'QUERY_SUCCEEDED'>;

type Actions =
  | SelectDatabaseAction
  | SelectTableAction
  | SelectColumnAction
  | SearchAction
  | MarkQueryAsErrored
  | MarkQueryAsCanceled
  | MarkQueryAsProvisioning
  | MarkQueryAsRunning
  | MarkQueryAsSuccessful;

function reducer(state: State, action: Actions) {
  switch (action.type) {
    case 'SELECT_DATABASE':
      return {
        ...state,
        selectedDatabase: action.payload.database,
        selectedTable: null,
        selectedColumn: null,
        searchValue: '',
      };
    case 'SELECT_TABLE':
      return {
        ...state,
        selectedTable: action.payload.table,
        selectedColumn: null,
        searchValue: '',
      };
    case 'SELECT_COLUMN':
      return { ...state, selectedColumn: action.payload.column };
    case 'SEARCH_DATABASE':
      return { ...state, searchValue: action.payload.searchValue };
    case 'QUERY_ERRORED':
      return {
        ...state,
        globalErrorMessage: action.payload.message,
        queryStatus: 'errored' as const,
      };
    case 'QUERY_PROVISIONING':
      return { ...state, queryStatus: 'provisioning' as const, queryId: null };
    case 'QUERY_RUNNING':
      return {
        ...state,
        queryStatus: 'running' as const,
        queryId: action.payload.queryId,
        globalErrorMessage: '',
      };
    case 'QUERY_CANCELED':
      return { ...state, queryId: null, queryStatus: null };
    case 'QUERY_SUCCEEDED':
      return { ...state, queryStatus: 'succeeded' as const };
    default:
      throw new Error();
  }
}

const DataExplorerContext = React.createContext<{
  state: State;
  dispatch: (action: Actions) => void;
}>(undefined);

export const DataExplorerContextProvider: React.FC = ({ children }) => {
  const { urlParams, updateUrlParams } = useUrlParams<
    Pick<State, 'queryId' | 'selectedDatabase'>
  >();

  const initialState = React.useMemo(
    () => ({
      queryId: urlParams.queryId || null,
      selectedDatabase: urlParams.selectedDatabase || storage.local.read(SELECTED_DATABASE_STORAGE_KEY) || null, // prettier-ignore
      selectedTable: null,
      selectedColumn: null,
      searchValue: '',
      globalErrorMessage: '',
      queryStatus: null,
    }),
    []
  );

  const [state, dispatch] = React.useReducer<React.Reducer<State, Actions>>(reducer, initialState);

  // sync changes to `queryId` and `selectedDatabase` to the URL
  React.useEffect(() => {
    updateUrlParams({ queryId: state.queryId, selectedDatabase: state.selectedDatabase });
  }, [state.queryId, state.selectedDatabase, updateUrlParams]);

  // always store the "last selected database" in the localStorage, to use it when a user
  // "comes back". Of course if a particular `selectedDatabase` is specified in the URL, it takes
  // precedence over the locally stored value (since it will refer to a particular query)
  React.useEffect(() => {
    return () => storage.local.write(SELECTED_DATABASE_STORAGE_KEY, state.selectedDatabase);
  }, [state.selectedDatabase]);

  const contextValue = React.useMemo(() => ({ state, dispatch }), [state, dispatch]);

  return (
    <DataExplorerContext.Provider value={contextValue}>{children}</DataExplorerContext.Provider>
  );
};

export const useDataExplorerContext = () => React.useContext(DataExplorerContext);

export const withDataExplorerContext = (Component: React.FC) => props => (
  <DataExplorerContextProvider>
    <Component {...props} />
  </DataExplorerContextProvider>
);
