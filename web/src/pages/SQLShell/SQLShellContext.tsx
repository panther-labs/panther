import React from 'react';
import useUrlParams from 'Hooks/useUrlParams';

type State = {
  selectedDatabase: string | null;
  selectedTable: string | null;
  selectedColumn: string | null;
  searchValue: string;
  globalErrorMessage: string;
  queryId?: string | null;
  querySql: string;
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
type SetGlobalErrorAction = Action<'SET_ERROR', { message: string }>;
type SetQueryId = Action<'SET_QUERY_ID', { queryId: string }>;
type SetQuerySql = Action<'SET_QUERY_SQL', { sql: string }>;
type SetQueryStatus = Action<'SET_QUERY_STATUS', { status: State['queryStatus'] }>;

type Actions =
  | SelectDatabaseAction
  | SelectTableAction
  | SelectColumnAction
  | SearchAction
  | SetGlobalErrorAction
  | SetQueryId
  | SetQuerySql
  | SetQueryStatus;

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
    case 'SET_ERROR':
      return {
        ...state,
        globalErrorMessage: action.payload.message,
        queryStatus: 'errored' as const,
      };
    case 'SET_QUERY_ID':
      return { ...state, queryId: action.payload.queryId, queryStatus: null };
    case 'SET_QUERY_SQL':
      return { ...state, querySql: action.payload.sql };
    case 'SET_QUERY_STATUS':
      return {
        ...state,
        queryStatus: action.payload.status,
        globalErrorMessage: action.payload.status !== 'errored' ? '' : state.globalErrorMessage,
      };
    default:
      throw new Error();
  }
}

const SQLShellContext = React.createContext<{
  state: State;
  dispatch: (action: Actions) => void;
}>(undefined);

export const SQLShellContextProvider: React.FC = ({ children }) => {
  const { urlParams, updateUrlParams } = useUrlParams<
    Pick<State, 'queryId' | 'selectedDatabase'>
  >();

  const initialState = React.useMemo(
    () => ({
      queryId: urlParams.queryId || null,
      selectedDatabase: urlParams.selectedDatabase || null,
      selectedTable: null,
      selectedColumn: null,
      searchValue: '',
      globalErrorMessage: '',
      querySql: '',
      queryStatus: null,
    }),
    []
  );

  const [state, dispatch] = React.useReducer<React.Reducer<State, Actions>>(reducer, initialState);

  React.useEffect(() => {
    updateUrlParams({ queryId: state.queryId, selectedDatabase: state.selectedDatabase });
  }, [state.queryId, state.selectedDatabase, updateUrlParams]);

  const contextValue = React.useMemo(() => ({ state, dispatch }), [state, dispatch]);

  return <SQLShellContext.Provider value={contextValue}>{children}</SQLShellContext.Provider>;
};

export const useSQLShellContext = () => React.useContext(SQLShellContext);

export const withSQLShellContext = (Component: React.FC) => props => (
  <SQLShellContextProvider>
    <Component {...props} />
  </SQLShellContextProvider>
);
