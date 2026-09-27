import { useEffect, useState, type ReactNode } from "react";
import { ApiError, fetchList } from "./api";

export interface Column<T> {
  header: string;
  render: (row: T) => ReactNode;
}

interface Props<T> {
  resource: string;
  columns: Column<T>[];
}

type State<T> = { rows: T[] } | { error: string } | null;

// ResourceTable is the one generic list view behind all 5 pages
// (ADR 0013: list-only scope) — every endpoint has the same shape
// (fetch an array, render rows), so one component parametrized by
// resource name + column definitions replaces 5 near-identical ones.
//
// It never resets its own state from inside the effect (that pattern
// trips oxlint's react(set-state-in-effect) rule, for good reason — it
// forces an extra render on every dependency change). Instead the
// caller remounts a fresh instance by changing `key` (e.g. when the
// token on the Settings page changes), which reinitializes `state` to
// null for free.
export function ResourceTable<T extends { ID: string }>({ resource, columns }: Props<T>) {
  const [state, setState] = useState<State<T>>(null);

  useEffect(() => {
    fetchList<T>(resource)
      .then((rows) => setState({ rows }))
      .catch((err: unknown) => {
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          setState({ error: `${err.message} — set a valid token on the Settings page.` });
        } else {
          setState({ error: err instanceof Error ? err.message : String(err) });
        }
      });
  }, [resource]);

  if (state === null) return <p>Loading…</p>;
  if ("error" in state) return <p className="error">{state.error}</p>;
  if (state.rows.length === 0) return <p>No results.</p>;

  return (
    <table>
      <thead>
        <tr>
          {columns.map((c) => (
            <th key={c.header}>{c.header}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {state.rows.map((row) => (
          <tr key={row.ID}>
            {columns.map((c) => (
              <td key={c.header}>{c.render(row)}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
